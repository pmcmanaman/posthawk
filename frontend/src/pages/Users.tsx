import { useState } from 'react'
import { PlusIcon } from '@heroicons/react/20/solid'
import UserTable from '../components/UserTable'
import AddUserModal from '../components/AddUserModal'

export default function Users() {
  const [isAddUserOpen, setIsAddUserOpen] = useState(false)

  return (
    <div>
      <div className="sm:flex sm:items-center">
        <div className="sm:flex-auto">
          <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:truncate sm:text-3xl sm:tracking-tight">
            Users
          </h1>
          <p className="mt-2 text-sm text-gray-700">
            Manage all system users and their permissions
          </p>
        </div>
        <div className="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
          <button
            type="button"
            onClick={() => setIsAddUserOpen(true)}
            className="inline-flex items-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
          >
            <PlusIcon className="-ml-0.5 mr-1.5 h-5 w-5" />
            Add User
          </button>
        </div>
      </div>
      <div className="mt-8 flow-root">
        <div className="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
          <div className="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
            <UserTable />
          </div>
        </div>
      </div>

      <AddUserModal open={isAddUserOpen} setOpen={setIsAddUserOpen} />
    </div>
  )
}
