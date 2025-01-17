import { useQuery } from '@tanstack/react-query'
import { KeyIcon } from '@heroicons/react/20/solid'

interface ApiKey {
  id: string
  name: string
  key: string
  createdAt: string
  lastUsed?: string
}

export default function ApiKeyTable() {
  const { data: apiKeys = [] } = useQuery<ApiKey[]>({
    queryKey: ['apiKeys'],
    queryFn: async () => {
      // TODO: Replace with actual API call
      return [
        {
          id: '1',
          name: 'Production Key',
          key: 'phk_1234567890abcdef',
          createdAt: '2023-01-01',
          lastUsed: '2023-10-01'
        },
        {
          id: '2',
          name: 'Development Key',
          key: 'phk_abcdef1234567890',
          createdAt: '2023-02-15'
        }
      ]
    }
  })

  return (
    <table className="min-w-full divide-y divide-gray-300">
      <thead>
        <tr>
          <th scope="col" className="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-0">
            Name
          </th>
          <th scope="col" className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
            Key
          </th>
          <th scope="col" className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
            Created At
          </th>
          <th scope="col" className="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">
            Last Used
          </th>
          <th scope="col" className="relative py-3.5 pl-3 pr-4 sm:pr-0">
            <span className="sr-only">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-200">
        {apiKeys.map((apiKey) => (
          <tr key={apiKey.id}>
            <td className="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-0">
              <div className="flex items-center">
                <KeyIcon className="h-5 w-5 flex-shrink-0 text-gray-400 mr-2" />
                {apiKey.name}
              </div>
            </td>
            <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
              {apiKey.key}
            </td>
            <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
              {new Date(apiKey.createdAt).toLocaleDateString()}
            </td>
            <td className="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
              {apiKey.lastUsed ? new Date(apiKey.lastUsed).toLocaleDateString() : 'Never'}
            </td>
            <td className="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-0">
              <button
                className="text-indigo-600 hover:text-indigo-900"
                onClick={() => navigator.clipboard.writeText(apiKey.key)}
              >
                Copy<span className="sr-only">, {apiKey.name}</span>
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
