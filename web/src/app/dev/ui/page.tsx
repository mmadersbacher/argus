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
} from "@/components/ui";
import { useState } from "react";

export default function UiGallery() {
  const [textValue, setTextValue] = useState("");
  const [checkboxValue, setCheckboxValue] = useState(false);
  const [indeterminateValue, setIndeterminateValue] = useState(false);
  const [radioValue, setRadioValue] = useState("option1");

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
      <Panel title="SkeletonTable">
        <SkeletonTable rows={3} cols={4} />
      </Panel>
    </div>
  );
}
