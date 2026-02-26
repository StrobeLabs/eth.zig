import '@/app/global.css';
import { RootProvider } from 'fumadocs-ui/provider/next';
import { Inter } from 'next/font/google';
import type { Metadata } from 'next';

const inter = Inter({
  subsets: ['latin'],
});

const SEO_DESCRIPTION = 'The fastest Ethereum library. Pure Zig. Zero dependencies. Beats alloy.rs on 19/26 benchmarks.';

const webSiteSchema = JSON.stringify({
  '@context': 'https://schema.org',
  '@type': 'WebSite',
  name: 'eth.zig Documentation',
  url: 'https://ethzig.org',
  description: SEO_DESCRIPTION,
  publisher: {
    '@type': 'Organization',
    name: 'Strobe Labs',
    url: 'https://strobelabs.com',
  },
});

const softwareSchema = JSON.stringify({
  '@context': 'https://schema.org',
  '@type': 'SoftwareSourceCode',
  name: 'eth.zig',
  description: 'The fastest Ethereum library. Pure Zig. Zero dependencies.',
  codeRepository: 'https://github.com/StrobeLabs/eth.zig',
  programmingLanguage: 'Zig',
  license: 'https://opensource.org/licenses/MIT',
  runtimePlatform: 'Zig >= 0.15.2',
});

export const metadata: Metadata = {
  metadataBase: new URL('https://ethzig.org'),
  title: {
    default: 'eth.zig Documentation',
    template: '%s | eth.zig',
  },
  description: SEO_DESCRIPTION,
  keywords: ['eth.zig', 'ethereum', 'zig', 'blockchain', 'web3', 'abi', 'secp256k1', 'keccak', 'erc20', 'json-rpc', 'alloy', 'zero dependencies', 'comptime'],
  openGraph: {
    title: 'eth.zig -- The Fastest Ethereum Library',
    description: SEO_DESCRIPTION,
    siteName: 'eth.zig',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'eth.zig -- The Fastest Ethereum Library',
    description: SEO_DESCRIPTION,
    creator: '@StrobeLabs',
  },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={inter.className} suppressHydrationWarning>
      <head>
        <script type="application/ld+json">{webSiteSchema}</script>
        <script type="application/ld+json">{softwareSchema}</script>
      </head>
      <body className="flex flex-col min-h-screen">
        <RootProvider
          theme={{
            defaultTheme: 'system',
            attribute: 'class',
            enableSystem: true,
            disableTransitionOnChange: false,
          }}
        >
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
