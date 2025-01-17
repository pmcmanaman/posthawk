import { useState } from 'react'
import { Button } from 'antd'
import { ApiKeyTable } from '../components/ApiKeyTable'
import { AddApiKeyModal } from '../components/AddApiKeyModal'

export function ApiKeys() {
  const [isModalVisible, setIsModalVisible] = useState(false)

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Button type="primary" onClick={() => setIsModalVisible(true)}>
          Add API Key
        </Button>
      </div>
      <ApiKeyTable />
      <AddApiKeyModal
        visible={isModalVisible}
        onClose={() => setIsModalVisible(false)}
        onSuccess={() => setIsModalVisible(false)}
      />
    </div>
  )
}
