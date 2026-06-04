import { ArgusMark } from "@/components/argus-mark";
import { MarkA, MarkEye, MarkNodes, MarkRadar } from "@/components/marks";
import type { ComponentType } from "react";

type Mark = ComponentType<{ size?: number }>;

const candidates: { id: number; name: string; Mark: Mark; note: string }[] = [
  { id: 1, name: "Eye v2 — refined iris/lens", Mark: MarkEye, note: "Wächter-Motiv, verfeinert: konzentrische Iris (Sensor / Linse)." },
  { id: 2, name: "Monogram A", Mark: MarkA, note: "Geometrisches „A\" mit Apex-Node — abstrakt, klassisch SaaS." },
  { id: 3, name: "Radar Sweep", Mark: MarkRadar, note: "Scan-Ringe + erkanntes Asset — Discovery-Motiv." },
  { id: 4, name: "Asset Graph", Mark: MarkNodes, note: "Vernetzte Knoten — CAASM-Beziehungen (Assets + Edges)." },
];

function Specimens({ Mark }: { Mark: Mark }) {
  return (
    <div className="mt-4 flex flex-wrap items-center gap-4">
      {/* on navy (sidebar context) */}
      <span className="flex h-14 w-14 items-center justify-center rounded-xl bg-sidebar text-white">
        <Mark size={30} />
      </span>
      {/* favicon-size tile */}
      <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent text-white">
        <Mark size={20} />
      </span>
      {/* on white */}
      <span className="flex h-14 w-14 items-center justify-center rounded-xl border border-line text-[#0f1e3d]">
        <Mark size={30} />
      </span>
      {/* horizontal lockup */}
      <span className="flex items-center gap-2">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent text-white">
          <Mark size={20} />
        </span>
        <span className="text-lg font-bold tracking-wide text-[#0f1e3d]">ARGUS</span>
      </span>
    </div>
  );
}

export default function BrandPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Argus — Logo-Marken zur Auswahl</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted">
          Vier Alternativen, jeweils auf Navy (Sidebar-Kontext), in Favicon-Größe, auf
          Weiß und als horizontales Lockup. Sag mir die <span className="font-medium text-fg">Nummer</span> —
          dann promote ich sie zur App-Marke (Sidebar + Favicon + Lockup-SVG).
        </p>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {candidates.map(({ id, name, Mark, note }) => (
          <div key={id} className="rounded-xl border border-line bg-surface p-5">
            <div className="flex items-center gap-2">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent text-xs font-bold text-white">
                {id}
              </span>
              <h2 className="font-semibold">{name}</h2>
            </div>
            <p className="mt-1 text-xs text-muted">{note}</p>
            <Specimens Mark={Mark} />
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-dashed border-line bg-surface-2 p-5">
        <h2 className="font-semibold">Aktuell verbaut · Eye v1 (simpel)</h2>
        <p className="mt-1 text-xs text-muted">Das ist die Marke, die gerade in der Sidebar + im Favicon steckt.</p>
        <Specimens Mark={ArgusMark} />
      </div>
    </div>
  );
}
