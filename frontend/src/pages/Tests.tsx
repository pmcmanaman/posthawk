import { useState } from 'react'
import { PlayIcon } from '@heroicons/react/20/solid'
import TestResultsTable from '../components/TestResultsTable'
import RunTestModal from '../components/RunTestModal'

export default function Tests() {
  const [isRunTestOpen, setIsRunTestOpen] = useState(false)

  return (
    <div>
      <div className="sm:flex sm:items-center">
        <div className="sm:flex-auto">
          <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:truncate sm:text-3xl sm:tracking-tight">
            Tests
          </h1>
          <p className="mt-2 text-sm text-gray-700">
            Run and view test results for email address validation
          </p>
        </div>
        <div className="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
          <button
            type="button"
            onClick={() => setIsRunTestOpen(true)}
            className="inline-flex items-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
          >
            <PlayIcon className="-ml-0.5 mr-1.5 h-5 w-5" />
            Run Test
          </button>
        </div>
      </div>
      <div className="mt-8 flow-root">
        <div className="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div className="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
            <TestResultsTable />
          </div>
        </div>
      </div>

      <RunTestModal open={isRunTestOpen} setOpen={setIsRunTestOpen} />
    </div>
  )
}
