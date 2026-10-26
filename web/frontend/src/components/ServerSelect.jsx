export default function ServerSelect({ servers, value, onChange, allowAll = true, id }) {
  return (
    <select
      id={id}
      className="input"
      value={value ?? ''}
      onChange={(event) => onChange(event.target.value ? Number(event.target.value) : null)}
    >
      {allowAll ? <option value="">Все серверы</option> : null}
      {servers.map((server) => (
        <option key={server.id} value={server.id}>
          {server.name} ({server.ip})
        </option>
      ))}
    </select>
  )
}
