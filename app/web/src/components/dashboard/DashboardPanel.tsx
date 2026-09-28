"use client";

import type { ReactNode } from "react";
import * as Tabs from "@radix-ui/react-tabs";
import { CollapsibleCard } from "@/components/ui/collapsible-card";

export function DashboardPanel({
  title,
  storageKey,
  tabs,
}: {
  title: string;
  storageKey: string;
  tabs: { label: string; content: ReactNode }[];
}) {
  return (
    <Tabs.Root defaultValue={tabs[0].label} className="min-w-0">
      <CollapsibleCard
        title={title}
        storageKey={storageKey}
        contentClassName="p-0"
      >
        <Tabs.List
          aria-label={`${title} views`}
          className="flex gap-4 overflow-x-auto border-b border-line px-4 sm:px-5"
        >
          {tabs.map(({ label }) => (
            <Tabs.Trigger
              key={label}
              value={label}
              className="-mb-px shrink-0 border-b-2 border-transparent py-2.5 text-[13px] font-medium text-muted outline-offset-[-3px] hover:text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-brand data-[state=active]:border-ink data-[state=active]:text-ink"
            >
              {label}
            </Tabs.Trigger>
          ))}
        </Tabs.List>
        {tabs.map(({ label, content }) => (
          <Tabs.Content
            key={label}
            value={label}
            aria-label={label}
            className="min-w-0 focus-visible:outline focus-visible:outline-2 focus-visible:outline-brand"
          >
            {content}
          </Tabs.Content>
        ))}
      </CollapsibleCard>
    </Tabs.Root>
  );
}
