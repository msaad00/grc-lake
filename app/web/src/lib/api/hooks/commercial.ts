import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "@/lib/api/client";
import type {
  BillingStatus,
  PlatformFeatures,
  ScimToken,
} from "@/lib/api/types";
import { STALE, type Opts } from "./shared";

export function usePlatformFeatures() {
  return useQuery({
    queryKey: ["platform", "features"],
    // A server that predates the probe is "unknown", not an API failure.
    queryFn: async (): Promise<PlatformFeatures | null> => {
      try {
        return await api.platformFeatures();
      } catch (error) {
        if (error instanceof ApiError && [404, 501].includes(error.status))
          return null;
        throw error;
      }
    },
    staleTime: Infinity,
    retry: false,
  });
}

export type CommercialFeature = Exclude<
  keyof PlatformFeatures,
  "commercial_hosted"
>;

/**
 * Probe once, then call a commercial route only when the server serves it, so
 * an off feature never produces a 501 (which browsers log as a console error).
 * A server without the probe falls back to calling the route; panels still
 * hide on 501 there.
 */
export function useCommercialFeature(feature: CommercialFeature): {
  known: boolean;
  enabled: boolean;
} {
  const features = usePlatformFeatures();
  if (features.isPending) return { known: false, enabled: false };
  if (features.isError || !features.data) return { known: true, enabled: true };
  return { known: true, enabled: Boolean(features.data[feature]) };
}

export function useScimTokens(opts?: Opts<ScimToken[]>) {
  return useQuery({
    queryKey: ["scim-tokens"],
    queryFn: api.scimTokens,
    staleTime: STALE,
    retry: false,
    ...opts,
  });
}

export function useCreateScimTokenMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.createScimToken(name),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scim-tokens"] });
    },
  });
}

export function useRevokeScimTokenMutation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (tokenId: string) => api.revokeScimToken(tokenId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scim-tokens"] });
    },
  });
}

export function useBilling(opts?: Opts<BillingStatus>) {
  return useQuery({
    queryKey: ["billing"],
    queryFn: api.billing,
    staleTime: STALE,
    retry: false,
    ...opts,
  });
}

export function useBillingCheckoutMutation() {
  return useMutation({
    mutationFn: (plan: string) => api.billingCheckout(plan),
  });
}

export function useBillingPortalMutation() {
  return useMutation({ mutationFn: () => api.billingPortal() });
}
