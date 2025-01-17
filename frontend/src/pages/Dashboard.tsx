export default function Dashboard() {
  return (
    <div>
      <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:truncate sm:text-3xl sm:tracking-tight">
        Dashboard
      </h1>
      <div className="mt-6">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-base font-semibold leading-6 text-gray-900">
                Total Validations
              </h3>
              <div className="mt-2 text-3xl font-bold tracking-tight text-gray-900">
                1,234
              </div>
            </div>
          </div>
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-base font-semibold leading-6 text-gray-900">
                Active Users
              </h3>
              <div className="mt-2 text-3xl font-bold tracking-tight text-gray-900">
                42
              </div>
            </div>
          </div>
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-base font-semibold leading-6 text-gray-900">
                API Requests
              </h3>
              <div className="mt-2 text-3xl font-bold tracking-tight text-gray-900">
                12,345
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
