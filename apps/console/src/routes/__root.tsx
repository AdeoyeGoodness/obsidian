import { HeadContent, Scripts, createRootRoute } from '@tanstack/react-router';
import { useEffect } from 'react';

import appCss from '../styles.css?url';
import { ThemeProvider } from '@/contexts/theme-context';

export const Route = createRootRoute({
  head: () => ({
    meta: [
      {
        charSet: 'utf-8',
      },
      {
        name: 'viewport',
        content: 'width=device-width, initial-scale=1',
      },
      {
        title: 'Pleroma CyberNet',
      },
    ],
    links: [
      {
        rel: 'stylesheet',
        href: appCss,
      },
    ],
  }),

  shellComponent: RootDocument,
});

function RootDocument({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('pleroma-theme') || 'dark';
      document.documentElement.setAttribute('data-theme', saved);
    }
  }, []);

  return (
    <html lang="en" className="h-full">
      <head>
        <HeadContent />
      </head>
      <body className="h-full overflow-hidden">
        <ThemeProvider>{children}</ThemeProvider>
        <Scripts />
      </body>
    </html>
  );
}
