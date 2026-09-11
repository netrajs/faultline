import { EmptyState } from '@/components/ui/StateViews';

export function GraphExplorer() {
  return (
    <EmptyState
      icon="topology-star-3"
      title="Graph Explorer is coming in a later phase"
      description={
        <>
          This is where the identity and asset graph gets walked directly — node by node, edge by
          edge — including the naive-reachability query run live next to the engine's own count.
          That side-by-side is the clearest demonstration of what precondition-aware search buys
          over plain graph traversal, and it deserves its own build pass rather than a rushed one
          here.
        </>
      }
    />
  );
}
