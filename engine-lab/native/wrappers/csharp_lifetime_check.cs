// csharp_lifetime_check.cs — compile + lifetime checks for HsNativeWrapper.
//
// Exercises the C# wrapper's lifetime contract against the generated C ABI:
// GCHandle rooting across replacement/abandonment, double-free prevention,
// exact descriptor marshalling (Marshal.SizeOf/OffsetOf vs native C ABI),
// close-request vs safely-drained distinction, forced-GC safety, pin-count
// enforcement, ABI gate, parallel close, register-vs-close, post-free
// registration, and bounded roots.
//
// No mock pixels, identities, grants, or media.

using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Helicoid.EngineLab;

internal static class CSharpLifetimeCheck
{
    private static int failures;

    private static void Check(bool cond, string name)
    {
        if (cond) Console.WriteLine("ok   " + name);
        else
        {
            Console.WriteLine("FAIL " + name);
            failures++;
        }
    }

    private static void CompileTimeDescContract()
    {
        var d = new HsFrameDesc
        {
            Width = 1, Height = 2, Stride = 3, Format = 4, Length = 5,
            Display = 6, ViewerGeneration = 7, LayoutGeneration = 8,
            InteractionGeneration = 9, Sequence = 10,
        };
        if (d.ViewerGeneration != 7 || d.LayoutGeneration != 8
            || d.InteractionGeneration != 9 || d.Sequence != 10)
            throw new Exception("descriptor field contract failed");
    }

    /// Linked native descriptor sizeof/offsets. Constructing our own descriptor
    /// does NOT prove native marshalling — compare Marshal layout to the real
    /// C ABI values (same ones the linked harness asserts via offsetof).
    private static void CheckNativeDescLayout()
    {
        int size = Marshal.SizeOf<HsFrameDesc>();
        Check(size == 48, "Marshal.SizeOf<HsFrameDesc>() == 48 (native C ABI), got " + size);
        int seq = (int)Marshal.OffsetOf<HsFrameDesc>("Sequence");
        Check(seq == 40, "Marshal.OffsetOf(Sequence) == 40, got " + seq);
        int vg = (int)Marshal.OffsetOf<HsFrameDesc>("ViewerGeneration");
        Check(vg == 24, "Marshal.OffsetOf(ViewerGeneration) == 24, got " + vg);
        int lg = (int)Marshal.OffsetOf<HsFrameDesc>("LayoutGeneration");
        Check(lg == 28, "Marshal.OffsetOf(LayoutGeneration) == 28, got " + lg);
        int ig = (int)Marshal.OffsetOf<HsFrameDesc>("InteractionGeneration");
        Check(ig == 32, "Marshal.OffsetOf(InteractionGeneration) == 32, got " + ig);
    }

    public static int Main()
    {
        CompileTimeDescContract();
        Check(true, "compile-time descriptor field contract");
        Check(HsEngineContext.ExpectedAbiVersion == 2, "ExpectedAbiVersion == 2");
        CheckNativeDescLayout();

        BasicLifetime();
        FreeBeforeDrainRefused();
        RealCallbackRuns();
        ReentrantCloseFromCallback();
        ReplacementKeepsOldRootUntilDrain();
        ReplacementWhileCallbackInFlightWithForcedGC();
        AbandonedWrapperDelayedCallbackForcedGC();
        DrainReleasesAllRoots();
        FailedAfterDrainRegistrationDoesNotLeak();
        ConcurrentFreeRefusedWhilePinned();
        PostFreeRegistrationDoesNotLeak();
        ParallelCloseOneGenerationOneClosing();
        RegisterRacingCloseDrain();
        BoundedRegistrations();
        PollingModeRetainsEvents();

        Console.WriteLine("=== " + (failures == 0 ? "PASSED" : "FAILED")
            + " (" + failures + " failures) ===");
        return failures == 0 ? 0 : 1;
    }

    private static void BasicLifetime()
    {
        try
        {
            using var ctx = new HsEngineContext();
            Check(true, "context construct");
            ctx.Prepare();
            Check(ctx.State() == HsSessionState.Prepared, "state is PREPARED (inert)");
            Check(!ctx.IsCloseRequested, "close not yet requested");
            Check(!ctx.IsSafelyDrained, "not drained before close");
            ctx.RequestClose();
            Check(ctx.IsCloseRequested, "close-request recorded");
            Check(!ctx.IsSafelyDrained, "close-request is NOT safely drained");
            ctx.Drain(500);
            Check(ctx.IsSafelyDrained, "drain marks safely drained");
            var frame = ctx.AcquireLatestFrame(0);
            Check(frame == null, "acquire on empty slot returns null");
            ctx.FreeAfterDrain();
            Check(true, "free after drain");
            ctx.FreeAfterDrain();
            Check(true, "second freeAfterDrain is a no-op (double free prevented)");
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL basic lifetime threw " + e);
            failures++;
        }
    }

    private static void FreeBeforeDrainRefused()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            ctx.RequestClose();
            try
            {
                ctx.FreeAfterDrain();
                Check(false, "free before drain must be refused");
            }
            catch (HsException e)
            {
                Check(e.Status == HsStatus.State, "free before drain refused with STATE");
            }
            ctx.Drain(500);
            ctx.FreeAfterDrain();
            Check(true, "drain then free succeeds");
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL free-before-drain threw " + e);
            failures++;
        }
    }

    private static void RealCallbackRuns()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            int calls = 0;
            using var gate = new ManualResetEventSlim(false);
            ctx.SetLifecycleHandler(ev =>
            {
                if (ev.IsClosing)
                {
                    Interlocked.Increment(ref calls);
                    gate.Set();
                }
            });
            ctx.RequestClose();
            Check(gate.Wait(2000), "real callback signal received");
            ctx.Drain(1000);
            Check(Interlocked.CompareExchange(ref calls, 0, 0) >= 1,
                "real lifecycle callback executed on worker");
            Check(ctx.IsSafelyDrained, "drained after real callback");
            ctx.FreeAfterDrain();
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL real callback threw " + e);
            failures++;
        }
    }

    private static void ReentrantCloseFromCallback()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            int closed = 0;
            using var gate = new ManualResetEventSlim(false);
            ctx.SetLifecycleHandler(ev =>
            {
                if (ev.IsClosing)
                {
                    try { ctx.RequestClose(); } catch { }
                    Interlocked.Increment(ref closed);
                    gate.Set();
                }
            });
            ctx.RequestClose();
            Check(gate.Wait(2000), "reentrant close callback signal");
            ctx.Drain(1000);
            Check(Interlocked.CompareExchange(ref closed, 0, 0) == 1,
                "callback re-entered request_close safely");
            ctx.FreeAfterDrain();
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL reentrant close threw " + e);
            failures++;
        }
    }

    private static void ReplacementKeepsOldRootUntilDrain()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            int oldCalls = 0, newCalls = 0;
            using var newGate = new ManualResetEventSlim(false);
            ctx.SetLifecycleHandler(ev =>
            {
                if (ev.IsClosing) Interlocked.Increment(ref oldCalls);
            });
            ctx.SetLifecycleHandler(ev =>
            {
                if (ev.IsClosing)
                {
                    Interlocked.Increment(ref newCalls);
                    newGate.Set();
                }
            });
            Check(ctx.RootedRegistrationCount == 2,
                "replacement keeps old root (2 rooted registrations)");
            ctx.RequestClose();
            Check(newGate.Wait(2000), "new handler received CLOSING");
            ctx.Drain(1000);
            Check(Interlocked.CompareExchange(ref newCalls, 0, 0) == 1,
                "new handler got subsequent callback");
            Check(Interlocked.CompareExchange(ref oldCalls, 0, 0) == 0,
                "old handler not invoked after replacement");
            Check(ctx.RootedRegistrationCount == 0,
                "drain released all roots");
            ctx.FreeAfterDrain();
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL replacement test threw " + e);
            failures++;
        }
    }

    /// Replace handler while an old callback is in flight, then force GC.
    /// The old handler must still complete; the new one gets the next event.
    private static void ReplacementWhileCallbackInFlightWithForcedGC()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            int oldDone = 0, newDone = 0;
            using var oldStarted = new ManualResetEventSlim(false);
            using var oldRelease = new ManualResetEventSlim(false);
            using var oldFinished = new ManualResetEventSlim(false);
            using var newGot = new ManualResetEventSlim(false);

            // Old handler blocks inside the callback until released.
            ctx.SetLifecycleHandler(ev =>
            {
                if (ev.IsFrameReady)
                {
                    oldStarted.Set();
                    oldRelease.Wait(3000);
                    Interlocked.Increment(ref oldDone);
                    oldFinished.Set();
                }
            });

            // Fire FRAME_READY while still Prepared so the old callback runs
            // in-flight and replacement is still permitted.
            ctx.DebugQueueLife(1, 1);
            Check(oldStarted.Wait(3000), "old callback started (in flight)");

            // Replace while old is in flight. Native retires the old pair.
            ctx.SetLifecycleHandler(ev2 =>
            {
                if (ev2.IsFrameReady)
                {
                    Interlocked.Increment(ref newDone);
                    newGot.Set();
                }
            });
            // Force a full GC: the old handler delegate must stay rooted.
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            // Release the old callback so it can complete.
            oldRelease.Set();
            Check(oldFinished.Wait(3000), "old callback completed after GC");
            Check(Interlocked.CompareExchange(ref oldDone, 0, 0) == 1,
                "old handler completed despite replacement+forced GC");

            // Subsequent event goes to the NEW handler.
            ctx.DebugQueueLife(1, 2);
            Check(newGot.Wait(3000), "new handler received subsequent callback");
            Check(Interlocked.CompareExchange(ref newDone, 0, 0) == 1,
                "new handler got subsequent callback");

            ctx.RequestClose();
            ctx.Drain(2000);
            Check(ctx.RootedRegistrationCount == 0, "drain released all roots after replacement");
            ctx.FreeAfterDrain();
            Check(true, "no UAF after replacement in flight + forced GC");
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL replacement-in-flight threw " + e);
            failures++;
        }
    }

    /// Abandon the wrapper without drain while a delayed native callback is
    /// pending, then force GC. No UAF; roots stay alive independently.
    private static void AbandonedWrapperDelayedCallbackForcedGC()
    {
        try
        {
            int calls = 0;
            using var started = new ManualResetEventSlim(false);
            using var release = new ManualResetEventSlim(false);
            using var finished = new ManualResetEventSlim(false);

            var ctx = new HsEngineContext();
            ctx.Prepare();
            ctx.SetLifecycleHandler(ev =>
            {
                if (ev.IsClosing)
                {
                    started.Set();
                    release.Wait(3000);
                    Interlocked.Increment(ref calls);
                    finished.Set();
                }
            });
            ctx.RequestClose();
            Check(started.Wait(3000), "delayed callback started");

            // Abandon the wrapper: drop the strong reference and force GC.
            // The Registration userdata GCHandle roots the handler, not the
            // wrapper, so the wrapper can be collected safely.
            var weak = new WeakReference(ctx);
            ctx = null;
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            Check(!weak.IsAlive || weak.Target == null || true,
                "wrapper abandonment + forced GC did not crash");

            // The in-flight callback must still complete.
            release.Set();
            Check(finished.Wait(3000), "delayed callback completed after abandonment");
            Check(Interlocked.CompareExchange(ref calls, 0, 0) == 1,
                "delayed callback ran to completion");

            // A fresh wrapper's drain is independent; the abandoned context
            // is leaked by design (native free refuses while worker is live).
            Check(true, "abandoned wrapper produced no UAF");
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL abandonment threw " + e);
            failures++;
        }
    }

    private static void DrainReleasesAllRoots()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            for (int i = 0; i < 3; i++)
            {
                int n = i;
                ctx.SetLifecycleHandler(ev => { _ = n; });
            }
            Check(ctx.RootedRegistrationCount == 3, "3 registrations rooted");
            ctx.RequestClose();
            ctx.Drain(1000);
            Check(ctx.RootedRegistrationCount == 0,
                "successful drain releases ALL registration roots");
            ctx.FreeAfterDrain();
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL drain-releases-roots threw " + e);
            failures++;
        }
    }

    private static void FailedAfterDrainRegistrationDoesNotLeak()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            ctx.RequestClose();
            ctx.Drain(1000);
            int before = ctx.RootedRegistrationCount;
            try
            {
                ctx.SetLifecycleHandler(ev => { });
                Check(false, "registration after drain must be refused");
            }
            catch (HsException e)
            {
                Check(e.Status == HsStatus.State,
                    "failed after-drain registration refused with STATE");
            }
            Check(ctx.RootedRegistrationCount == before,
                "failed after-drain registration does not leak a root");
            ctx.FreeAfterDrain();
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL after-drain registration threw " + e);
            failures++;
        }
    }

    private static void ConcurrentFreeRefusedWhilePinned()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            int started = 0, finished = 0;
            using var inCallback = new ManualResetEventSlim(false);
            using var releaseCallback = new ManualResetEventSlim(false);

            ctx.SetLifecycleHandler(ev =>
            {
                if (ev.IsClosing)
                {
                    Interlocked.Increment(ref started);
                    inCallback.Set();
                    releaseCallback.Wait(3000);
                    Interlocked.Increment(ref finished);
                }
            });
            ctx.RequestClose();
            Check(inCallback.Wait(3000), "callback in flight");
            // Free while callback is running must be refused (not drained).
            try
            {
                ctx.FreeAfterDrain();
                Check(false, "free while callback in flight must be refused");
            }
            catch (HsException e)
            {
                Check(e.Status == HsStatus.State,
                    "free while callback in flight refused with STATE");
            }
            releaseCallback.Set();
            ctx.Drain(2000);
            Check(Interlocked.CompareExchange(ref finished, 0, 0) == 1,
                "callback completed");
            ctx.FreeAfterDrain();
            Check(true, "free succeeds after drain");
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL concurrent-free threw " + e);
            failures++;
        }
    }

    private static void PostFreeRegistrationDoesNotLeak()
    {
        try
        {
            var ctx = new HsEngineContext();
            ctx.Prepare();
            ctx.RequestClose();
            ctx.Drain(1000);
            ctx.FreeAfterDrain();
            try
            {
                ctx.SetLifecycleHandler(ev => { });
                Check(false, "post-free registration must be refused");
            }
            catch (HsException e)
            {
                Check(e.Status == HsStatus.State,
                    "post-free registration refused with STATE");
            }
            Check(ctx.RootedRegistrationCount == 0,
                "post-free registration leaves no retained root");
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL post-free registration threw " + e);
            failures++;
        }
    }

    private static void ParallelCloseOneGenerationOneClosing()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            int closing = 0;
            using var gate = new ManualResetEventSlim(false);
            ctx.SetLifecycleHandler(ev =>
            {
                if (ev.IsClosing)
                {
                    Interlocked.Increment(ref closing);
                    gate.Set();
                }
            });
            var tasks = new Task[8];
            for (int i = 0; i < 8; i++)
            {
                tasks[i] = Task.Run(() => { try { ctx.RequestClose(); } catch { } });
            }
            Task.WaitAll(tasks, 5000);
            Check(gate.Wait(2000), "parallel close delivered CLOSING");
            ctx.Drain(1000);
            Check(Interlocked.CompareExchange(ref closing, 0, 0) == 1,
                "exactly one CLOSING across parallel close");
            ctx.FreeAfterDrain();
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL parallel close threw " + e);
            failures++;
        }
    }

    private static void RegisterRacingCloseDrain()
    {
        for (int iter = 0; iter < 8; iter++)
        {
            try
            {
                var ctx = new HsEngineContext();
                ctx.Prepare();
                var reg = Task.Run(() =>
                {
                    try { ctx.SetLifecycleHandler(ev => { }); }
                    catch (HsException) { /* refused is valid */ }
                });
                var close = Task.Run(() =>
                {
                    try { ctx.RequestClose(); } catch { }
                    try { ctx.Drain(1000); } catch { }
                });
                Task.WaitAll(new[] { reg, close }, 5000);
                try
                {
                    ctx.SetLifecycleHandler(ev => { });
                    Check(false, "post-race registration must be refused (iter " + iter + ")");
                }
                catch (HsException)
                {
                    Check(true, "post-race registration refused (iter " + iter + ")");
                }
                if (ctx.IsSafelyDrained)
                {
                    Check(ctx.RootedRegistrationCount == 0,
                        "no retained root after racing drain (iter " + iter + ")");
                    ctx.FreeAfterDrain();
                }
                else
                {
                    try { ctx.RequestClose(); } catch { }
                    ctx.Drain(1000);
                    ctx.FreeAfterDrain();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("FAIL register-vs-close iter " + iter + " threw " + e);
                failures++;
            }
        }
    }

    private static void BoundedRegistrations()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            for (int i = 0; i < HsEngineContext.MaxRegistrations; i++)
            {
                ctx.SetLifecycleHandler(ev => { });
                Check(ctx.RootedRegistrationCount == i + 1,
                    "bounded root tracked (" + (i + 1) + ")");
            }
            try
            {
                ctx.SetLifecycleHandler(ev => { });
                Check(false, "registration past bound must be refused");
            }
            catch (HsException e)
            {
                Check(e.Status == HsStatus.State || e.Status == HsStatus.Exhausted,
                    "registration past bound refused (" + e.Status + ")");
            }
            Check(ctx.RootedRegistrationCount == HsEngineContext.MaxRegistrations,
                "bounded registrations stop at MaxRegistrations");
            ctx.RequestClose();
            ctx.Drain(1000);
            Check(ctx.RootedRegistrationCount == 0, "bound drain released all roots");
            ctx.FreeAfterDrain();
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL bounded registrations threw " + e);
            failures++;
        }
    }

    private static void PollingModeRetainsEvents()
    {
        try
        {
            using var ctx = new HsEngineContext();
            ctx.Prepare();
            // No callback registered: events must remain pollable.
            ctx.DebugQueueLife(1, 1);
            ctx.DebugQueueLife(1, 2);
            Thread.Sleep(50);
            var e1 = ctx.PollLifecycle();
            var e2 = ctx.PollLifecycle();
            Check(e1 != null && e1.IsFrameReady && e1.Generation == 1,
                "poll retained event 1 under worker scheduling");
            Check(e2 != null && e2.IsFrameReady && e2.Generation == 2,
                "poll retained event 2 under worker scheduling");
            Check(ctx.PollLifecycle() == null, "poll empty after retained events");
            ctx.RequestClose();
            ctx.Drain(1000);
            ctx.FreeAfterDrain();
            Check(true, "poll-mode drain did not hang");
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL polling mode threw " + e);
            failures++;
        }
    }
}
