import { useCallback, useEffect, useRef, useState } from 'react';

import { prefersReducedMotion } from '@/theme/motion';
import './IntroSplash.css';

// A bespoke, one-off duration for a single cinematic moment -- not part of
// the reusable duration scale in tokens.css, and mirrored exactly in
// IntroSplash.css so the JS unmount timer and the CSS transition agree.
const EXIT_MS = 900;

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
