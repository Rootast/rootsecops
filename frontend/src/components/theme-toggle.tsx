"use client";

import { useTheme } from "next-themes";
import { useSyncExternalStore } from "react";
import { Button } from "@/components/ui/button";
import { Moon, Sun } from "lucide-react";
import { motion } from "framer-motion";

export function ThemeToggle() {
  const { setTheme, theme } = useTheme();
  const mounted = useSyncExternalStore(
    () => () => {},
    () => true,
    () => false
  );

  if (!mounted) {
    return (
      <Button
        variant="outline"
        size="icon"
        className="h-11 w-11 rounded-full border border-zinc-800/60 bg-black/40"
        disabled
        aria-hidden
      />
    );
  }

  const isDark = theme === "dark";

  return (
    <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.97 }}>
      <Button
        variant="outline"
        size="icon"
        aria-label="Toggle theme"
        onClick={() => setTheme(isDark ? "light" : "dark")}
        className="h-11 w-11 rounded-full border border-zinc-700 bg-black/40 text-zinc-200 hover:border-blue-500/60 hover:bg-blue-500/10"
      >
        <motion.div
          key={theme}
          initial={{ rotate: -90, opacity: 0 }}
          animate={{ rotate: 0, opacity: 1 }}
          transition={{ duration: 0.25 }}
        >
          {isDark ? (
            <Sun className="h-5 w-5 text-amber-300" />
          ) : (
            <Moon className="h-5 w-5 text-blue-500" />
          )}
        </motion.div>
      </Button>
    </motion.div>
  );
}
