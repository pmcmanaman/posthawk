import { useState } from 'react'
import { Layout as AntLayout, Menu, Button, theme } from 'antd'
import { useAuth } from '../context/AuthContext'
import { TestResultsTable } from './TestResultsTable'
import { ApiKeyTable } from './ApiKeyTable'
import { AddUserModal } from './AddUserModal'
import { AddApiKeyModal } from './AddApiKeyModal'

const { Header, Content, Sider } = AntLayout

export function Layout() {
  const { user, logout } = useAuth()
  const [selectedMenu, setSelectedMenu] = useState('tests')
  const [addUserModalVisible, setAddUserModalVisible] = useState(false)
  const [addApiKeyModalVisible, setAddApiKeyModalVisible] = useState(false)
  
  const {
    token: { colorBgContainer },
  } = theme.useToken()

  const handleMenuSelect = ({ key }: { key: string }) => {
    setSelectedMenu(key)
  }

  const renderContent = () => {
    switch (selectedMenu) {
      case 'tests':
        return <TestResultsTable />
      case 'api-keys':
        return <ApiKeyTable />
      default:
        return <TestResultsTable />
    }
  }

  if (!user) {
    return null // Or render login component
  }

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      <Header style={{ padding: '0 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ color: 'white', fontSize: '18px' }}>
          API Test Dashboard
        </div>
        <div>
          <Button type="primary" onClick={() => setAddApiKeyModalVisible(true)} style={{ marginRight: 16 }}>
            Add API Key
          </Button>
          <Button type="primary" onClick={() => setAddUserModalVisible(true)} style={{ marginRight: 16 }}>
            Add User
          </Button>
          <Button onClick={logout}>
            Logout
          </Button>
        </div>
      </Header>
      <AntLayout>
        <Sider width={200} style={{ background: colorBgContainer }}>
          <Menu
            mode="inline"
            selectedKeys={[selectedMenu]}
            onSelect={handleMenuSelect}
            style={{ height: '100%', borderRight: 0 }}
            items={[
              { key: 'tests', label: 'Tests' },
              { key: 'api-keys', label: 'API Keys' },
            ]}
          />
        </Sider>
        <AntLayout style={{ padding: '24px' }}>
          <Content style={{ padding: 24, margin: 0, background: colorBgContainer }}>
            {renderContent()}
          </Content>
        </AntLayout>
      </AntLayout>

      <AddUserModal
        visible={addUserModalVisible}
        onClose={() => setAddUserModalVisible(false)}
        onSuccess={() => {
          setAddUserModalVisible(false)
          // Optionally refresh data
        }}
      />

      <AddApiKeyModal
        visible={addApiKeyModalVisible}
        onClose={() => setAddApiKeyModalVisible(false)}
        onSuccess={() => {
          setAddApiKeyModalVisible(false)
          // Refresh API keys list if visible
          if (selectedMenu === 'api-keys') {
            // Trigger refresh
          }
        }}
      />
    </AntLayout>
  )
}
