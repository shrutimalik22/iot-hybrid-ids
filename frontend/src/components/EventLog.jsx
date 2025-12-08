// frontend/src/components/EventLog.jsx
import React from "react";

const sevBadgeClass = (sev) => {
  switch (sev) {
    case "high":
      return "bg-red-500/15 text-red-200 border-red-500/60";
    case "medium":
      return "bg-amber-500/10 text-amber-100 border-amber-500/50";
    default:
      return "bg-emerald-500/10 text-emerald-100 border-emerald-500/40";
  }
};

/**
 * EventLog
 * - Parent (SectionCard) height fix karega, yeh hamesha usse full fill karega.
 * - Andar events ke liye scroll.
 */
export default function EventLog({ events = [], className = "" }) {
  return (
    <div
      className={
        "flex h-full min-h-0 flex-col rounded-2xl border border-slate-800 bg-slate-950/85 text-xs " +
        className
      }
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800/80">
        <div className="flex flex-col">
          <h3 className="text-[13px] font-semibold text-slate-100">
            Security Events
          </h3>
          <p className="text-[10px] text-slate-500">
            Hybrid IDS detections in real-time.
          </p>
        </div>
        <span className="rounded-full bg-slate-900/80 px-2 py-[2px] text-[10px] text-slate-300">
          {events.length} events
        </span>
      </div>

      {/* Scrollable list */}
      <div className="flex-1 min-h-0 overflow-y-auto px-3 py-2.5 space-y-1.5 custom-scrollbar">
        {events.length === 0 && (
          <div className="mt-2 text-[11px] text-slate-500">
            No events yet. Launch an attack from the simulator to see logs here.
          </div>
        )}

        {events.map((e) => (
          <div
            key={e.id}
            className={`flex flex-col gap-0.5 rounded-lg border px-2.5 py-1.5 ${sevBadgeClass(
              e.severity
            )}`}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className="truncate text-[11px] font-semibold">
                  {e.device_name}
                </span>
                <span className="text-[9px] text-slate-300/80">
                  {e.ip_address}
                </span>
              </div>
              <span className="shrink-0 rounded-full bg-slate-950/70 px-1.5 py-[2px] text-[9px] uppercase tracking-wide">
                {e.event_type}
              </span>
            </div>

            <div className="text-[10px] text-slate-100 leading-snug">
              {e.message}
            </div>

            {e.scores &&
              (e.scores.combined !== undefined ||
                e.scores.rule !== undefined ||
                e.scores.anom !== undefined) && (
                <div className="text-[9px] text-slate-200/90">
                  Score:
                  {e.scores.combined !== undefined &&
                    ` hybrid=${e.scores.combined.toFixed(2)}`}
                  {e.scores.rule !== undefined &&
                    ` rule=${e.scores.rule.toFixed(2)}`}
                  {e.scores.anom !== undefined &&
                    ` anom=${e.scores.anom.toFixed(2)}`}
                </div>
              )}

            {e.label_hint && (
              <div className="text-[9px] text-sky-300/90">
                Reason: {e.label_hint}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}










// // frontend/src/components/EventLog.jsx
// import React from "react";

// const sevBadge = (sev) => {
//   switch (sev) {
//     case "high":
//       return "bg-red-500/15 text-red-300 border-red-500/60";
//     case "medium":
//       return "bg-amber-500/10 text-amber-200 border-amber-500/50";
//     default:
//       return "bg-emerald-500/10 text-emerald-200 border-emerald-500/40";
//   }
// };

// export default function EventLog({ events }) {
//   return (
//     <div className="h-72 overflow-y-auto rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-xs">
//       <div className="mb-2 flex items-center justify-between">
//         <h3 className="text-[13px] font-semibold text-slate-100">
//           Security Events
//         </h3>
//         <span className="text-[10px] text-slate-500">{events.length} events</span>
//       </div>
//       <div className="space-y-1.5">
//         {events.map((e) => (
//           <div
//             key={e.id}
//             className={`flex flex-col gap-0.5 rounded-lg border px-2 py-1.5 ${sevBadge(
//               e.severity
//             )}`}
//           >
//             <div className="flex items-center justify-between">
//               <div className="flex items-center gap-2">
//                 <span className="text-[11px] font-semibold">
//                   {e.device_name}
//                 </span>
//                 <span className="text-[9px] text-slate-400">{e.ip_address}</span>
//               </div>
//               <span className="rounded-full bg-slate-900/70 px-1.5 py-[1px] text-[9px] uppercase tracking-wide">
//                 {e.event_type}
//               </span>
//             </div>
//             <div className="text-[10px] text-slate-100">{e.message}</div>
//             {e.scores && (e.scores.combined || e.scores.rule || e.scores.anom) && (
//               <div className="text-[9px] text-slate-300">
//                 Score:
//                 {e.scores.combined !== undefined &&
//                   ` hybrid=${e.scores.combined.toFixed(2)}`}
//                 {e.scores.rule !== undefined &&
//                   ` rule=${e.scores.rule.toFixed(2)}`}
//                 {e.scores.anom !== undefined &&
//                   ` anom=${e.scores.anom.toFixed(2)}`}
//               </div>
//             )}
//             {e.label_hint && (
//               <div className="text-[9px] text-sky-300/90">
//                 Reason: {e.label_hint}
//               </div>
//             )}
//           </div>
//         ))}
//         {events.length === 0 && (
//           <div className="text-[11px] text-slate-500">
//             No events yet. Start an attack to see Hybrid IDS detection.
//           </div>
//         )}
//       </div>
//     </div>
//   );
// }
