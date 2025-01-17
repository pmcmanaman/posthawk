import { useQuery } from '@tanstack/react-query'
import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/20/solid'

interface TestResult {
  id: string
  email: string
  result: boolean
  timestamp: string
  details?: string
}

export default function TestResultsTable() {
  const { data: testResults = [] } = useQuery<TestResult[]>({
    queryKey: ['testResults'],
    queryFn: async () => {
      // TODO: Replace with actual API call
      return [
        {
          id: '1',
          email: 'test@example.com',
          result: true,
          timestamp: '2023-10-01T12:34:56Z',
          details: 'Valid email address'
        },
        {
          id: '2',
          email: 'invalid@example',
          result: false,
          timestamp: '2023-10-01T12:35:10Z',
          details: 'Invalid domain'
        }
      ]
    }
  })

  return (
    <table className="min-w-full divide-y divide-gray-300">
      <thead>
        <tr>
          <th scope="col" className="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-0">
            Email
          </th>
          <th scope="col" className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
            Result
          </th>
          <th scope="col" className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
            Timestamp
          </th>
          <th scope="col" className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
            Details
          </th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-200">
        {testResults.map((test) => (
          <tr key={test.id}>
            <td className="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-0">
              {test.email}
            </td>
            <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
              {test.result ? (
                <span className="inline-flex items-center gap-x-1.5 rounded-md bg-green-100 px-2 py-1 text-xs font-medium text-green-700">
                  <CheckCircleIcon className="h-4 w-4" />
                  Valid
                </span>
              ) : (
                <span className="inline-flex items-center gap-x-1.5 rounded-md bg-red-100 px-2 py-1 text-xs font-medium text-red-700">
                  <XCircleIcon className="h-4 w-4" />
                  Invalid
                </span>
              )}
            </td>
            <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
              {new Date(test.timestamp).toLocaleString()}
            </td>
            <td className="px-3 py-4 text-sm text-gray-500">
              {test.details}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
