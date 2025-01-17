import { useState, useEffect } from 'react'
import { Table, Button, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'

interface ApiKey {
  id: string
  key: string
  name: string
  createdAt: string
  lastUsedAt: string | null
  isActive: boolean
}

export function ApiKeyTable() {
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchApiKeys()
  }, [])

  const fetchApiKeys = async () => {
    try {
      const response = await fetch('/api/api-keys', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      })
      
      if (!response.ok) {
        throw new Error('Failed to fetch API keys')
      }
      
      const data = await response.json()
      setKeys(data)
    } catch (error) {
      console.error('Error fetching API keys:', error)
      message.error('Failed to fetch API keys')
    } finally {
      setLoading(false)
    }
  }

  const handleDeactivate = async (id: string) => {
    try {
      const response = await fetch(`/api/api-keys/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      })

      if (!response.ok) {
        throw new Error('Failed to deactivate API key')
      }

      message.success('API key deactivated successfully')
      fetchApiKeys() // Refresh the list
    } catch (error) {
      console.error('Error deactivating API key:', error)
      message.error('Failed to deactivate API key')
    }
  }

  const columns: ColumnsType<ApiKey> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: 'API Key',
      dataIndex: 'key',
      key: 'key',
      render: (key: string) => `${key.slice(0, 8)}...${key.slice(-8)}`,
    },
    {
      title: 'Created',
      dataIndex: 'createdAt',
      key: 'createdAt',
      render: (date: string) => new Date(date).toLocaleString(),
    },
    {
      title: 'Last Used',
      dataIndex: 'lastUsedAt',
      key: 'lastUsedAt',
      render: (date: string | null) => date ? new Date(date).toLocaleString() : 'Never',
    },
    {
      title: 'Status',
      dataIndex: 'isActive',
      key: 'isActive',
      render: (isActive: boolean) => (
        <span style={{ color: isActive ? 'green' : 'red' }}>
          {isActive ? 'Active' : 'Inactive'}
        </span>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: unknown, record: ApiKey) => (
        record.isActive ? (
          <Button 
            danger 
            onClick={() => handleDeactivate(record.id)}
          >
            Deactivate
          </Button>
        ) : null
      ),
    },
  ]

  return (
    <Table 
      columns={columns} 
      dataSource={keys}
      loading={loading}
      rowKey="id"
    />
  )
}
