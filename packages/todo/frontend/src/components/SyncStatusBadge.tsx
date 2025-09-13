import React from "react";
import { useStatus } from "@powersync/react";
import { BoltIcon } from "@heroicons/react/24/outline";

export function SyncStatusBadge({ className = "" }: { className?: string }) {
  const status = useStatus();

  const syncing = !!(
    status.dataFlowStatus?.downloading || status.dataFlowStatus?.uploading
  );
  let label = "Offline";
  if (status.connecting) label = "Connecting…";
  else if (status.connected && syncing) label = "Syncing…";
  else if (status.connected) label = "Synced";
  return (
    <span className={`badge inline-flex items-center gap-1 ${className}`}>
      <BoltIcon className="h-4 w-4" /> {label}
    </span>
  );
}

export default SyncStatusBadge;
