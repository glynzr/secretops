'use client'
import { useState, useEffect } from 'react'
import { api, Organization } from '@/lib/api'
import Sidebar from '@/components/layout/Sidebar'
import OrgSelectorPage from '@/components/orgs/OrgSelectorPage'
import DashboardPage from '@/components/dashboard/DashboardPage'
import IntegrationsPage from '@/components/integrations/IntegrationsPage'
import ProjectsPage from '@/components/projects/ProjectsPage'
import FindingsPage from '@/components/findings/FindingsPage'
import RemediationPage from '@/components/remediation/RemediationPage'

export type Page = 'dashboard' | 'integrations' | 'projects' | 'findings' | 'remediation'

export default function Home() {
  const [orgs, setOrgs]               = useState<Organization[]>([])
  const [orgId, setOrgId]             = useState<string | null>(null)
  const [page, setPage]               = useState<Page>('dashboard')
  const [activeScanId, setActiveScanId] = useState('')
  const [orgsLoading, setOrgsLoading] = useState(true)
  const [showOrgSelector, setShowOrgSelector] = useState(false)

  const refreshOrgs = () =>
    api.listOrgs().then(list => { setOrgs(list); return list }).catch(() => [] as Organization[])

  useEffect(() => {
    api.listOrgs()
      .then(list => {
        setOrgs(list)
        if (list.length > 0) {
          const saved = typeof window !== 'undefined' ? localStorage.getItem('secretops_org') : null
          const found = saved ? list.find(o => o.id === saved) : null
          setOrgId(found ? found.id : list[0].id)
        }
      })
      .catch(() => {})
      .finally(() => setOrgsLoading(false))
  }, [])

  const selectOrg = (id: string) => {
    setOrgId(id)
    setPage('dashboard')
    setShowOrgSelector(false)
    if (typeof window !== 'undefined') localStorage.setItem('secretops_org', id)
  }

  const onOrgCreated = (org: Organization) => {
    setOrgs(prev => [...prev, org])
    selectOrg(org.id)
    setPage('integrations')
  }

  const goFindings = (scanId: string) => {
    setActiveScanId(scanId)
    setPage('findings')
  }

  if (orgsLoading) {
    return (
      <div style={{ display: 'flex', height: '100vh', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)', color: 'var(--muted)', fontSize: 13 }}>
        Loading...
      </div>
    )
  }

  if (orgs.length === 0 || !orgId || showOrgSelector) {
    return (
      <OrgSelectorPage
        orgs={orgs}
        onSelect={selectOrg}
        onCreate={onOrgCreated}
        onCancel={orgs.length > 0 && orgId ? () => setShowOrgSelector(false) : undefined}
      />
    )
  }

  const currentOrg = orgs.find(o => o.id === orgId)!

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg)' }}>
      <Sidebar
        active={page}
        onSelect={setPage}
        orgs={orgs}
        currentOrgId={orgId}
        onOrgSelect={selectOrg}
        onCreateOrg={() => setShowOrgSelector(true)}
      />
      <main style={{ flex: 1, overflowY: 'auto' }}>
        {page === 'dashboard'    && <DashboardPage orgId={orgId} org={currentOrg} onNavigate={setPage} onScanComplete={goFindings} />}
        {page === 'integrations' && <IntegrationsPage orgId={orgId} onReady={() => setPage('projects')} />}
        {page === 'projects'     && <ProjectsPage orgId={orgId} onScanComplete={goFindings} />}
        {page === 'findings'     && <FindingsPage orgId={orgId} scanId={activeScanId} onNavigate={setPage} />}
        {page === 'remediation'  && <RemediationPage orgId={orgId} />}
      </main>
    </div>
  )
}
