import { useState } from 'react'
import { Button } from 'antd'
import { AddUserModal } from '../components/AddUserModal'

export function Users() {
  const [isModalVisible, setIsModalVisible] = useState(false)

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Button type="primary" onClick={() => setIsModalVisible(true)}>
          Add User
        </Button>
      </div>
      <AddUserModal
        visible={isModalVisible}
        onClose={() => setIsModalVisible(false)}
        onSuccess={() => setIsModalVisible(false)}
      />
    </div>
  )
}
