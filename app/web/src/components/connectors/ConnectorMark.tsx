"use client";

import type { CSSProperties } from "react";
import {
  connectorBrandLogo,
  type ConnectorBrandLogo,
} from "@/lib/connector-brand-logos";
import { connectorVisual } from "@/lib/connector-visuals";

interface ConnectorMarkProps {
  connectorId: string;
  name?: string;
  category?: string;
  size?: "sm" | "md" | "lg";
  showVendor?: boolean;
  className?: string;
}

const SIZE: Record<
  NonNullable<ConnectorMarkProps["size"]>,
  { box: number; icon: number; mark: string; vendor: string }
> = {
  sm: { box: 40, icon: 22, mark: "text-[9px]", vendor: "text-[10px]" },
  md: { box: 44, icon: 24, mark: "text-[10px]", vendor: "text-[11px]" },
  lg: { box: 52, icon: 28, mark: "text-[11px]", vendor: "text-xs" },
};

function BrandSvg({
  brand,
  iconSize,
}: {
  brand: ConnectorBrandLogo;
  iconSize: number;
}) {
  const viewBox = brand.viewBox ?? "0 0 24 24";

  if (brand.paths?.length) {
    return (
      <svg
        role="img"
        viewBox={viewBox}
        width={iconSize}
        height={iconSize}
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden
      >
        <title>{brand.title}</title>
        {brand.paths.map((segment) => (
          <path
            key={segment.d.slice(0, 24)}
            d={segment.d}
            fill={segment.fill}
          />
        ))}
      </svg>
    );
  }

  if (brand.path && brand.hex) {
    return (
      <svg
        role="img"
        viewBox={viewBox}
        width={iconSize}
        height={iconSize}
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden
      >
        <title>{brand.title}</title>
        <path d={brand.path} fill={`#${brand.hex}`} />
      </svg>
    );
  }

  return null;
}

export function ConnectorMark({
  connectorId,
  name,
  category,
  size = "md",
  showVendor = false,
  className,
}: ConnectorMarkProps) {
  const brand = connectorBrandLogo(connectorId);
  const visual = connectorVisual(connectorId, { name, category });
  const dim = SIZE[size];
  const boxStyle: CSSProperties = {
    width: dim.box,
    height: dim.box,
  };
  const hasBrand =
    brand &&
    ((brand.path && brand.hex) || (brand.paths && brand.paths.length > 0));

  return (
    <span
      className={["inline-flex min-w-0 items-center gap-2.5", className]
        .filter(Boolean)
        .join(" ")}
      role="img"
      aria-label={`${visual.vendor} connector`}
      title={visual.vendor}
    >
      <span
        className="grid shrink-0 place-items-center rounded-xl border border-line bg-surface shadow-sm"
        style={boxStyle}
      >
        {hasBrand && brand ? (
          <BrandSvg brand={brand} iconSize={dim.icon} />
        ) : (
          <span
            className={[
              "grid h-full w-full place-items-center rounded-xl font-semibold tracking-wide",
              dim.mark,
            ].join(" ")}
            style={{ color: visual.accent, background: visual.bg }}
          >
            {visual.mark}
          </span>
        )}
      </span>
      {showVendor && (
        <span className="min-w-0 overflow-hidden">
          <span
            className={[
              "block truncate font-semibold text-ink",
              dim.vendor,
            ].join(" ")}
          >
            {name ?? visual.vendor}
          </span>
          <span className="block truncate text-[10px] text-muted">
            {visual.categoryLabel}
          </span>
        </span>
      )}
    </span>
  );
}
