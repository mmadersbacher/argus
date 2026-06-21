"use client";
import { PageHeader, Panel, Button } from "@/components/ui";

export default function UiGallery() {
  return (
    <div className="mx-auto max-w-5xl p-8">
      <PageHeader title="UI Gallery" description="Dev-only primitive showcase." />
      <Panel title="Buttons">
        <div className="flex gap-2">
          <Button>Primary</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger">Danger</Button>
        </div>
      </Panel>
    </div>
  );
}
