import { useCallback, useEffect, useRef, useState } from 'react';

import { prefersReducedMotion } from '@/theme/motion';
import './IntroSplash.css';

// A bespoke, one-off duration for a single cinematic moment -- not part of
// the reusable duration scale in tokens.css, and mirrored exactly in
// IntroSplash.css (and in Dashboard's app-reveal counterpart in global.css)
// so the JS unmount timer and both CSS transitions agree to the millisecond.
const EXIT_MS = 1100;

// Start the cross-fade this far before the video's natural end, so the
// dashboard zooms in over footage that is still moving rather than over a
// frame that has already frozen on `ended`. The last stretch of the clip is
// simply never seen -- a clean cut into a live shot reads as far smoother
// than a perfectly complete but static one.
const CROSSFADE_LEAD_SECONDS = 1.5;

interface IntroSplashProps {
  /** Called the instant the video ends (or is skipped) -- starts the dashboard's own reveal in parallel with our fade/zoom-out. */
  onFinish: () => void;
  /** Called once our own exit transition has actually finished, so the parent can unmount us. */
  onExitComplete: () => void;
}

/**
 * A one-time intro: the network-graph video plays, then fades out while
 * zooming in as the dashboard simultaneously zooms in underneath it -- one
 * continuous cross-fade rather than a hard cut. Shown once per browser
 * session (see the sessionStorage check in App.tsx) and skipped outright
 * under prefers-reduced-motion, since autoplaying video is exactly what that
 * preference exists to suppress.
 */
export function IntroSplash({ onFinish, onExitComplete }: IntroSplashProps) {
  const [exiting, setExiting] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const finishedRef = useRef(false);

  const finish = useCallback(() => {
    if (finishedRef.current) return;
    finishedRef.current = true;
    setExiting(true);
    onFinish();
    window.setTimeout(onExitComplete, EXIT_MS);
  }, [onFinish, onExitComplete]);

  useEffect(() => {
    if (prefersReducedMotion()) {
      finish();
      return;
    }
    const video = videoRef.current;
    const playPromise = video?.play();
    // Autoplay can be blocked by the browser even when muted, in rare cases --
    // don't strand the visitor looking at a frozen first frame.
    if (playPromise && typeof playPromise.catch === 'function') {
      playPromise.catch(() => finish());
    }
  }, [finish]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' || event.key === 'Enter' || event.key === ' ') finish();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [finish]);

  const handleTimeUpdate = useCallback(() => {
    const video = videoRef.current;
    if (!video || !Number.isFinite(video.duration)) return;
    // Clamped so a clip shorter than 2x the lead time can't trigger the
    // cross-fade before it has even really started.
    const lead = Math.min(CROSSFADE_LEAD_SECONDS, video.duration / 2);
    if (video.duration - video.currentTime <= lead) finish();
  }, [finish]);

  return (
    <div
      className={`intro-splash${exiting ? ' intro-splash--exiting' : ''}`}
      onClick={finish}
      role="presentation"
    >
      <video
        ref={videoRef}
        className="intro-splash__video"
        src="/media/intro-network.mp4"
        muted
        playsInline
        autoPlay
        onTimeUpdate={handleTimeUpdate}
        onEnded={finish}
        onError={finish}
      />
      <div className="intro-splash__scrim" aria-hidden="true" />
      <button
        type="button"
        className="intro-splash__skip"
        onClick={(event) => {
          event.stopPropagation();
          finish();
        }}
      >
        Skip intro
      </button>
    </div>
  );
}
