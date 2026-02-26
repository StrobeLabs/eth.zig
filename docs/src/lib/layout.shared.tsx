import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: 'eth.zig',
    },
    githubUrl: 'https://github.com/StrobeLabs/eth.zig',
    links: [
      {
        text: 'Twitter',
        url: 'https://x.com/StrobeLabs',
        external: true,
      },
    ],
  };
}
