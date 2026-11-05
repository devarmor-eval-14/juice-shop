/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { XmlDocument, ParseOption } from 'libxml2-wasm'

const MAX_CATALOG_BYTES = 64 * 1024

// Business customers upload their product catalogue as XML; items are returned as parsed so the caller can confirm the import.
export function b2bCatalogImport () {
  return (req: Request, res: Response, next: NextFunction) => {
    const xml: string = typeof req.body === 'string' ? req.body : (req.body?.catalog ?? '')
    if (Buffer.byteLength(xml) > MAX_CATALOG_BYTES) {
      res.status(413)
      next(new Error('Catalogue exceeds the 64 KB limit'))
      return
    }
    try {
      const doc = XmlDocument.fromString(xml, { option: ParseOption.XML_PARSE_NONET | ParseOption.XML_PARSE_NOBLANKS })
      const items = doc.root.find('//item').map((node: any) => ({
        sku: node.get('sku')?.content,
        name: node.get('name')?.content,
        price: Number(node.get('price')?.content)
      }))
      doc.dispose()
      res.json({ cid: req.query.cid, imported: items.length, items })
    } catch (err) {
      next(err)
    }
  }
}
