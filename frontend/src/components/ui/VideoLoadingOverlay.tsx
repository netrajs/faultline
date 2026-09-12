import { useEffect, useRef } from 'react';

import { prefersReducedMotion } from '@/theme/motion';
import './VideoLoadingOverlay.css';

interface VideoLoadingOverlayProps {
  /** Whether a real operation is actually in flight -- this never shows on its own timer. */
  active: boolean;
  /** Plain-language description of what's running, e.g. "Applying fix and re-deriving affected paths…". */
  label: string;
}

/**
 * A full-screen "something real and possibly slow is happening" overlay,
 * reusing the same network-graph clip as the app's one-time intro -- but
 * looped for however long the operation actually takes, not a fixed
 * duration, and with no skip/cross-fade choreography: this is a busy
 * indicator, not an entrance. Mounted only while `active` is true, so an
 * instant response never shows it at all.
 *
 * Exists because a mutation like "apply this fix" triggers a full
 * re-derivation (docs/SCOPE.md D6) that can take a real amount of time --
 * the caller must not render a blank screen for that stretch.
 */
export function VideoLoadingOverlay({ active, label }: VideoLoadingOverlayProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const reduced = prefersReducedMotion();

  useEffect(() => {
    if (!active || reduced) return;
    const video = videoRef.current;
    // Autoplay can be blocked even when muted in rare cases -- if so the
    // static first frame plus the label below still communicates "working".
    void video?.play().catch(() => {});
  }, [active, reduced]);

  if (!active) return null;

  return (
    <div className="video-loading-overlay" role="status" aria-live="polite">
      {!reduced && (
        <video
          ref={videoRef}
          className="video-loading-overlay__video"
          src="/media/intro-network.mp4"
          muted
          loop
          playsInline
          autoPlay
        />
      )}
      <div className="video-loading-overlay__scrim" aria-hidden="true" />
      <div className="video-loading-overlay__content">
        <span className="video-loading-overlay__spinner" aria-hidden="true" />
        <p className="video-loading-overlay__label">{label}</p>
      </div>
    </div>
  );
}
