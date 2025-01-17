import { useState, useEffect } from 'react'
import { Table } from 'antd'
import type { ColumnsType } from 'antd/es/table'

interface TestResult {
  id: string
  email: string
  result: boolean
  timestamp: string
  details: string
}

export function TestResultsTable() {
  const [results, setResults] = useState<TestResult[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchTestResults()
  }, [])

  const fetchTestResults = async () => {
    try {
      const response = await fetch('/api/tests', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      })
      
      if (!response.ok) {
        throw new Error('Failed to fetch test results')
      }
      
      const data = await response.json()
      setResults(data)
    } catch (error) {
      console.error('Error fetching test results:', error)
    } finally {
      setLoading(false)
    }
  }

  const columns: ColumnsType<TestResult> = [
    {
      title: 'Email',
      dataIndex: 'email',
      key: 'email',
    },
    {
      title: 'Result',
      dataIndex: 'result',
      key: 'result',
      render: (result: boolean) => (
        <span style={{ color: result ? 'green' : 'red' }}>
          {result ? 'Pass' : 'Fail'}
        </span>
      ),
    },
    {
      title: 'Timestamp',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (timestamp: string) => new Date(timestamp).toLocaleString(),
    },
    {
      title: 'Details',
      dataIndex: 'details',
      key: 'details',
    },
  ]

  return (
    <Table 
      columns={columns} 
      dataSource={results}
      loading={loading}
      rowKey="id"
    />
  )
}
