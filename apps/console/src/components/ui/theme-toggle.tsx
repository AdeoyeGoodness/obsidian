import { Moon, Sun } from 'lucide-react';
import { useTheme } from '@/contexts/theme-context';
import { Button } from './button';

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();

  return (
    <Button
      onClick={toggleTheme}
      iconOnly
      ariaLabel={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      className="border-gray-700 text-gray-200 hover:text-white"
      showBrackets={false}
    >
      {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
    </Button>
  );
}

