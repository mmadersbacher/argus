"use client";
import { PageHeader, Panel, Button, Textarea } from "@/components/ui";
import { useState } from "react";

export default function UiGallery() {
  const [textValue, setTextValue] = useState("");

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
      <Panel title="Textarea">
        <Textarea
          placeholder="Enter your notes here..."
          rows={4}
          value={textValue}
          onChange={(e) => setTextValue(e.currentTarget.value)}
        />
        <p className="mt-2 text-xs text-muted">
          Current value length: {textValue.length}
        </p>
      </Panel>
    </div>
  );
}
