import { Button } from '@/components/ui/button';
import { useTheme } from '@/theme/theme-context';
import { LucideMoonStar, SunMedium } from 'lucide-react';

export function ThemeToggle() {
  const { isDark, toggleTheme } = useTheme();

  return (
    <Button
      icon={isDark ? <LucideMoonStar size={16} /> : <SunMedium size={16} />}
      intent="ghost"
      size="sm"
      onClick={toggleTheme}
      ariaLabel="Toggle theme"
      className="w-auto px-4 uppercase tracking-[0.2em]"
    >
      {isDark ? 'Dark Grid' : 'Light Grid'}
    </Button>
  );
}

