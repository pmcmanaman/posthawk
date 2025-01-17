import { Modal, Form, Input, message } from 'antd'
import { useState } from 'react'

interface Props {
  visible: boolean
  onClose: () => void
  onSuccess: () => void
}

export function AddUserModal({ visible, onClose, onSuccess }: Props) {
  const [form] = Form.useForm()
  const [loading, setLoading] = useState(false)

  const handleSubmit = async () => {
    try {
      setLoading(true)
      const values = await form.validateFields()
      
      const response = await fetch('/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(values)
      })

      if (!response.ok) {
        throw new Error('Failed to create user')
      }

      message.success('User created successfully')
      form.resetFields()
      onSuccess()
      onClose()
    } catch (error) {
      console.error('Error creating user:', error)
      message.error('Failed to create user')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal
      title="Add New User"
      open={visible}
      onOk={handleSubmit}
      onCancel={onClose}
      confirmLoading={loading}
    >
      <Form form={form} layout="vertical">
        <Form.Item
          name="email"
          label="Email"
          rules={[
            { required: true, message: 'Please enter an email' },
            { type: 'email', message: 'Please enter a valid email' }
          ]}
        >
          <Input placeholder="Enter email" />
        </Form.Item>
        <Form.Item
          name="password"
          label="Password"
          rules={[
            { required: true, message: 'Please enter a password' },
            { min: 8, message: 'Password must be at least 8 characters' }
          ]}
        >
          <Input.Password placeholder="Enter password" />
        </Form.Item>
        <Form.Item
          name="name"
          label="Name"
          rules={[{ required: true, message: 'Please enter a name' }]}
        >
          <Input placeholder="Enter name" />
        </Form.Item>
      </Form>
    </Modal>
  )
}
