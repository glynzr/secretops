import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'SecretOps — Secret Detection & Remediation Platform',
  description: 'AI-powered secrets scanning with automated remediation for GitLab repositories',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
