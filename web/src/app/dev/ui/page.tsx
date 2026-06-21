"use client";
import {
  PageHeader,
  Panel,
  Button,
  Textarea,
  Checkbox,
  Radio,
  Link,
  ButtonLink,
  Skeleton,
  SkeletonTable,
  Tabs,
  TabPanel,
  Pagination,
  Tooltip,
  Menu,
  ConfirmDialog,
} from "@/components/ui";
import { useState } from "react";

export default function UiGallery() {
  const [textValue, setTextValue] = useState("");
  const [checkboxValue, setCheckboxValue] = useState(false);
  const [indeterminateValue, setIndeterminateValue] = useState(false);
  const [radioValue, setRadioValue] = useState("option1");
  const [activeTab, setActiveTab] = useState("tab1");
  const [currentPage, setCurrentPage] = useState(1);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmed, setConfirmed] = useState<boolean | null>(null);

  return (
    <div className="mx-auto max-w-5xl p-8">
      <PageHeader
        title="UI Gallery"
        description="Dev-only primitive showcase."
      />
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
      <Panel title="Checkbox">
        <div className="space-y-3">
          <Checkbox
            checked={checkboxValue}
            onChange={setCheckboxValue}
            label="Accept terms"
          />
          <Checkbox
            checked={indeterminateValue}
            onChange={setIndeterminateValue}
            label="Optional setting"
            indeterminate={false}
          />
          <Checkbox
            checked={false}
            onChange={() => {}}
            label="Disabled checkbox"
            disabled
          />
        </div>
      </Panel>
      <Panel title="Radio">
        <div className="space-y-3">
          <Radio
            name="demo"
            value="option1"
            checked={radioValue === "option1"}
            onChange={setRadioValue}
            label="Option 1"
          />
          <Radio
            name="demo"
            value="option2"
            checked={radioValue === "option2"}
            onChange={setRadioValue}
            label="Option 2"
          />
          <Radio
            name="demo"
            value="option3"
            checked={radioValue === "option3"}
            onChange={setRadioValue}
            label="Option 3"
          />
          <Radio
            name="disabled-demo"
            value="disabled"
            checked={false}
            onChange={() => {}}
            label="Disabled radio"
            disabled
          />
        </div>
      </Panel>
      <Panel title="Link">
        <div className="flex flex-col gap-3">
          <Link href="/dev">Internal link</Link>
          <Link href="https://github.com" external>
            External link
          </Link>
          <Link href="https://docs.example.com" external icon>
            External link with icon
          </Link>
        </div>
      </Panel>
      <Panel title="ButtonLink">
        <div className="flex gap-2">
          <ButtonLink href="/dev" variant="primary">
            Primary
          </ButtonLink>
          <ButtonLink href="/dev" variant="secondary">
            Secondary
          </ButtonLink>
          <ButtonLink href="/dev" variant="ghost">
            Ghost
          </ButtonLink>
          <ButtonLink href="/dev" variant="danger">
            Danger
          </ButtonLink>
        </div>
      </Panel>
      <Panel title="Skeleton">
        <div className="space-y-4">
          <div className="flex gap-3 items-center">
            <Skeleton variant="circle" width={40} height={40} />
            <div className="space-y-2 flex-1">
              <Skeleton variant="text" width="60%" />
              <Skeleton variant="text" width="40%" />
            </div>
          </div>
          <Skeleton variant="rect" width="100%" height={200} />
        </div>
      </Panel>
      <Panel title="Tabs">
        <Tabs
          tabs={[
            { id: "tab1", label: "First" },
            { id: "tab2", label: "Second" },
            { id: "tab3", label: "Third" },
          ]}
          active={activeTab}
          onChange={setActiveTab}
        />
        <div className="mt-4">
          <TabPanel when="tab1" active={activeTab}>
            <p className="text-fg">First tab content</p>
          </TabPanel>
          <TabPanel when="tab2" active={activeTab}>
            <p className="text-fg">Second tab content</p>
          </TabPanel>
          <TabPanel when="tab3" active={activeTab}>
            <p className="text-fg">Third tab content</p>
          </TabPanel>
        </div>
      </Panel>
      <Panel title="SkeletonTable">
        <SkeletonTable rows={3} cols={4} />
      </Panel>
      <Panel title="Pagination">
        <Pagination
          page={currentPage}
          pageCount={5}
          onPageChange={setCurrentPage}
        />
      </Panel>
      <Panel title="Tooltip">
        <div className="flex gap-6 items-center flex-wrap">
          <Tooltip content="Top tooltip (default)">
            <Button variant="secondary">Hover / focus me</Button>
          </Tooltip>
          <Tooltip content="Right-side tooltip" side="right">
            <Button variant="secondary">Right</Button>
          </Tooltip>
          <Tooltip content="Bottom tooltip" side="bottom">
            <Button variant="secondary">Bottom</Button>
          </Tooltip>
          <Tooltip content="Left tooltip" side="left">
            <Button variant="secondary">Left</Button>
          </Tooltip>
        </div>
      </Panel>
      <Panel title="Menu">
        <div className="flex gap-4 items-start flex-wrap">
          <Menu
            trigger="Actions"
            items={[
              { label: "Edit", onSelect: () => alert("Edit clicked") },
              { label: "Duplicate", onSelect: () => alert("Duplicate clicked") },
              { separator: true },
              { label: "Delete", tone: "danger", onSelect: () => alert("Delete clicked") },
            ]}
          />
          <Menu
            trigger="Aligned end"
            align="end"
            items={[
              { label: "View details", onSelect: () => alert("View details") },
              { label: "Export", onSelect: () => alert("Export") },
              { separator: true },
              { label: "Archive", tone: "danger", onSelect: () => alert("Archive") },
            ]}
          />
          <Menu
            trigger="With disabled"
            items={[
              { label: "Enabled action", onSelect: () => alert("Enabled") },
              { label: "Disabled action", disabled: true, onSelect: () => {} },
            ]}
          />
        </div>
      </Panel>
      <Panel title="ConfirmDialog">
        <div className="flex items-center gap-4">
          <Button variant="danger" onClick={() => setConfirmOpen(true)}>
            Revoke API key…
          </Button>
          {confirmed !== null && (
            <p className="text-sm text-muted">
              Last action: {confirmed ? "confirmed" : "cancelled"}
            </p>
          )}
        </div>
        <ConfirmDialog
          open={confirmOpen}
          title="Revoke API key?"
          body="This will permanently revoke the key. Any integrations using it will stop working immediately."
          confirmLabel="Revoke"
          tone="danger"
          onConfirm={() => { setConfirmed(true); setConfirmOpen(false); }}
          onCancel={() => { setConfirmed(false); setConfirmOpen(false); }}
        />
      </Panel>
    </div>
  );
}
