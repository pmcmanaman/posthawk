import { Modal, Form, Input, message } from 'antd'
import { useState } from 'react'

interface Props {
  visible: boolean
  onClose: () => void
  onSuccess: () => void
}

export function AddApiKeyModal({ visible, onClose, onSuccess }: Props) {
  const [form] = Form.useForm()
  const [loading, setLoading] = useState(false)

  const handleSubmit = async () => {
    try {
      setLoading(true)
      const values = await form.validateFields()
      
      const response = await fetch('/api/api-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(values)
      })

      if (!response.ok) {
        throw new Error('Failed to create API key')
      }

      await response.json()
      message.success('API key created successfully')
      form.resetFields()
      onSuccess()
      onClose()
    } catch (error) {
      console.error('Error creating API key:', error)
      message.error('Failed to create API key')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal
      title="Add New API Key"
      open={visible}
      onOk={handleSubmit}
      onCancel={onClose}
      confirmLoading={loading}
    >
      <Form form={form} layout="vertical">
        <Form.Item
          name="name"
          label="Key Name"
          rules={[{ required: true, message: 'Please enter a name for the API key' }]}
        >
          <Input placeholder="Enter key name" />
        </Form.Item>
      </Form>
    </Modal>
  )
}
