"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import type { ReactNode } from "react";

interface ModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: "md" | "lg";
}

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  size = "md",
}: ModalProps) {
  const widthClass =
    size === "lg"
      ? "w-[min(760px,calc(100vw-32px))]"
      : "w-[min(560px,calc(100vw-32px))]";

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <AnimatePresence>
        {open && (
          <Dialog.Portal forceMount>
            <Dialog.Overlay asChild>
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px]"
              />
            </Dialog.Overlay>
            <div className="pointer-events-none fixed inset-0 z-50 grid place-items-center p-4">
              <Dialog.Content asChild>
                <motion.div
                  initial={{ opacity: 0, scale: 0.96, y: 12 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.96, y: 12 }}
                  className={`${widthClass} pointer-events-auto grid max-h-[calc(100dvh-40px)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden rounded-2xl bg-surface shadow-hero`}
                >
                  <header className="flex items-start justify-between gap-4 border-b border-line p-5">
                    <div>
                      <Dialog.Title className="text-lg font-semibold text-ink">
                        {title}
                      </Dialog.Title>
                      {description && (
                        <Dialog.Description className="mt-1 text-sm text-muted">
                          {description}
                        </Dialog.Description>
                      )}
                    </div>
                    <Dialog.Close
                      aria-label="Close"
                      className="grid h-8 w-8 place-items-center rounded-md text-muted hover:bg-surfaceMuted"
                    >
                      <X className="h-4 w-4" />
                    </Dialog.Close>
                  </header>
                  <div className="overflow-auto p-5">{children}</div>
                  {footer && (
                    <footer className="border-t border-line p-4">
                      {footer}
                    </footer>
                  )}
                </motion.div>
              </Dialog.Content>
            </div>
          </Dialog.Portal>
        )}
      </AnimatePresence>
    </Dialog.Root>
  );
}
