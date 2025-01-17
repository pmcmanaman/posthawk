import { useState } from 'react'
import { PlusIcon } from '@heroicons/react/20/solid'
import ApiKeyTable from '../components/ApiKeyTable'
import AddApiKeyModal from '../components/AddApiKeyModal'

export default function ApiKeys() {
  const [isAddKeyOpen, setIsAddKeyOpen] = useState(false)

  return (
    <div>
      <div className="sm:flex sm:items-center">
        <div className="sm:flex-auto">
          <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:truncate sm:text-3xl sm:tracking-tight">
            API Keys
          </h1>
          <p className="mt-2 text-sm text-gray-700">
            Manage API keys for accessing the PostHawk API
          </p>
        </div>
        <div className="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
          <button
            type="button"
            onClick={() => setIsAddKeyOpen(true)}
            className="inline-flex items-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
          >
            <PlusIcon className="-ml-0.5 mr-1.5 h-5 w-5" />
            Add API Key
          </button>
        </div>
      </div>
      <div className="mt-8 flow-root">
        <div className="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div className="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
            <ApiKeyTable />
          </div>
        </div>
      </div>

      <AddApiKeyModal open={isAddKeyOpen} setOpen={setIsAddKeyOpen} />
    </div>
  )
}
