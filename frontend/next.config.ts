import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'standalone',
  async rewrites() {
    return [
      {
        source: '/api/v1/:path*',
        destination: `${process.env.API_BACKEND_URL || 'http://api-backend:8080'}/api/v1/:path*`,
      },
    ]
  },
}

export default nextConfig
