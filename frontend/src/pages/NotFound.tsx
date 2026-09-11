import { Link } from 'react-router-dom';

import { EmptyState } from '@/components/ui/StateViews';

export function NotFound() {
  return (
    <EmptyState
      icon="compass-off"
      title="Not part of this build yet"
      description="This screen is on the roadmap but hasn't been built in this pass. The sidebar items marked “soon” route here on purpose."
    >
      <Link className="pill-button" to="/">
        Back to the dashboard
      </Link>
    </EmptyState>
  );
}
