import type { ReactNode } from "react";

interface Props {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}

/** The one page header: H1, an optional one-line description, and actions. */
export function PageHeader({ title, description, actions }: Props) {
  return (
    <div className="flex min-w-0 flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div className="min-w-0 max-w-3xl">
        <h1 className="ui-page-title">{title}</h1>
        {description ? (
          <p className="mt-1 text-sm leading-6 text-muted">{description}</p>
        ) : null}
      </div>
      {actions ? (
        <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">
          {actions}
        </div>
      ) : null}
    </div>
  );
}
