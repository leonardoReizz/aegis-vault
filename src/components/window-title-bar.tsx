import { useState, useCallback } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

export function WindowTitleBar({ children }: { children?: React.ReactNode }) {
  const [hovered, setHovered] = useState(false);

  const handleClose = useCallback(() => {
    getCurrentWindow().close();
  }, []);

  const handleMinimize = useCallback(() => {
    getCurrentWindow().minimize();
  }, []);

  const handleMaximize = useCallback(async () => {
    const win = getCurrentWindow();
    await win.toggleMaximize();
    await win.setFocus();
  }, []);

  const handleDoubleClick = useCallback(async (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest("button, input, [role='menuitem']"))
      return;
    const win = getCurrentWindow();
    await win.toggleMaximize();
    await win.setFocus();
  }, []);

  return (
    <div
      onDoubleClick={handleDoubleClick}
      className="sticky top-0 z-50 bg-background border-b border-border/40"
    >
      <div className="h-[52px] flex items-center px-4 relative">
        {/* Drag region — sits behind everything, only empty space triggers drag */}
        <div
          data-tauri-drag-region
          className="absolute inset-0"
        />

        {/* macOS-style traffic light buttons */}
        <div
          className="flex items-center gap-2 shrink-0 relative z-10"
          onMouseEnter={() => setHovered(true)}
          onMouseLeave={() => setHovered(false)}
        >
          {/* Close */}
          <button
            onClick={handleClose}
            className="group w-3 h-3 rounded-full bg-[#ff5f57] flex items-center justify-center transition-colors hover:bg-[#ff5f57]/80 focus:outline-none"
          >
            {hovered && (
              <svg
                width="6"
                height="6"
                viewBox="0 0 6 6"
                className="text-[#4d0000]"
              >
                <path
                  d="M0.5 0.5L5.5 5.5M5.5 0.5L0.5 5.5"
                  stroke="currentColor"
                  strokeWidth="1.2"
                  strokeLinecap="round"
                />
              </svg>
            )}
          </button>

          {/* Minimize */}
          <button
            onClick={handleMinimize}
            className="group w-3 h-3 rounded-full bg-[#febc2e] flex items-center justify-center transition-colors hover:bg-[#febc2e]/80 focus:outline-none"
          >
            {hovered && (
              <svg
                width="6"
                height="2"
                viewBox="0 0 6 2"
                className="text-[#995700]"
              >
                <path
                  d="M0.5 1H5.5"
                  stroke="currentColor"
                  strokeWidth="1.2"
                  strokeLinecap="round"
                />
              </svg>
            )}
          </button>

          {/* Maximize */}
          <button
            onClick={handleMaximize}
            className="group w-3 h-3 rounded-full bg-[#28c840] flex items-center justify-center transition-colors hover:bg-[#28c840]/80 focus:outline-none"
          >
            {hovered && (
              <svg
                width="6"
                height="6"
                viewBox="0 0 6 6"
                className="text-[#006500]"
              >
                <path
                  d="M1 1L5 1L5 5L1 5Z"
                  stroke="currentColor"
                  strokeWidth="1.1"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  fill="none"
                />
              </svg>
            )}
          </button>
        </div>

        {/* Content area — above drag region so interactions work normally */}
        {children && (
          <div className="flex-1 flex items-center ml-4 relative z-10">{children}</div>
        )}
      </div>
    </div>
  );
}
