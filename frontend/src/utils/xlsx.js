export function autoFitWorksheetColumns(worksheet, rows, options = {}) {
  const maxWidth = options.maxWidth ?? 70
  const minWidth = options.minWidth ?? 12
  const headers = rows?.length ? Object.keys(rows[0]) : []

  worksheet['!cols'] = headers.map((header) => {
    const maxLength = rows.reduce((max, row) => {
      const value = row?.[header]
      const text = value == null ? '' : String(value)
      const longestLine = text.split(/\r?\n/).reduce((lineMax, line) => Math.max(lineMax, line.length), 0)
      return Math.max(max, longestLine)
    }, String(header).length)

    return { wch: Math.min(Math.max(maxLength + 2, minWidth), maxWidth) }
  })

  const range = worksheet['!ref']
  if (!range) return

  for (const cellAddress of Object.keys(worksheet)) {
    if (cellAddress.startsWith('!')) continue
    worksheet[cellAddress].s = {
      ...(worksheet[cellAddress].s || {}),
      alignment: { wrapText: true, vertical: 'top' },
    }
  }
}
