'use client'
import { useState, useCallback } from 'react'
import Sidebar from '@/components/Sidebar'
import Dashboard from '@/components/views/Dashboard'
import FindingsView from '@/components/views/FindingsView'
import ScanView from '@/components/views/ScanView'
import { IntegrationsView } from '@/components/views/IntegrationsView'
import RepositoriesView from '@/components/views/RepositoriesView'
import { RemediationView } from '@/components/views/RemediationView'
import { AuditView } from '@/components/views/AuditView'

export type View = 'dashboard' | 'findings' | 'scan' | 'integrations' | 'repositories' | 'remediation' | 'audit'

export default function Home() {
  const [activeView, setActiveView] = useState<View>('dashboard')
  const [activeScanId, setActiveScanId] = useState<number | null>(null)

  const handleStartScan = useCallback((scanId: number) => {
    setActiveScanId(scanId)
    setActiveView('scan')
  }, [])

  return (
    <div className="flex h-screen overflow-hidden bg-canvas">
      <Sidebar activeView={activeView} onNavigate={setActiveView} />
      <main className="flex-1 overflow-auto">
        {activeView === 'dashboard'    && <Dashboard onStartScan={handleStartScan} onNavigate={setActiveView} />}
        {activeView === 'findings'     && <FindingsView />}
        {activeView === 'scan'         && <ScanView scanId={activeScanId} onNavigate={setActiveView} />}
        {activeView === 'integrations' && <IntegrationsView />}
        {activeView === 'repositories' && <RepositoriesView onStartScan={handleStartScan} />}
        {activeView === 'remediation'  && <RemediationView />}
        {activeView === 'audit'        && <AuditView />}
      </main>
    </div>
  )
}
