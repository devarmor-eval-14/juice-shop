/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const ALLOWED_IMAGE_HOSTS = ['images.unsplash.com', 'i.imgur.com', 'upload.wikimedia.org', 'avatars.githubusercontent.com']
const EXTENSION_BY_CONTENT_TYPE: Record<string, string> = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif' }
const MAX_IMAGE_BYTES = 2 * 1024 * 1024
const FETCH_TIMEOUT_MS = 5000

function isPrivateAddress (address: string) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
  }
  const lower = address.toLowerCase()
  return lower === '::1' || lower === '::' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80') || lower.startsWith('::ffff:')
}

async function validateImageUrl (raw: string) {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new Error('not a valid URL')
  }
  if (url.protocol !== 'https:') throw new Error('only https URLs are accepted')
  if (!ALLOWED_IMAGE_HOSTS.includes(url.hostname)) throw new Error('image host is not on the allow-list')
  const { address } = await dns.lookup(url.hostname)
  if (isPrivateAddress(address)) throw new Error('image host resolves to a non-public address')
  return url
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
      try {
        const url = await validateImageUrl(String(req.body.imageUrl))
        const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
        if (!response.ok || !response.body) {
          throw new Error('url returned a non-OK status code or an empty body')
        }
        const ext = EXTENSION_BY_CONTENT_TYPE[(response.headers.get('content-type') ?? '').split(';')[0].trim()]
        if (!ext) throw new Error('response is not a supported image type')
        if (Number(response.headers.get('content-length') ?? 0) > MAX_IMAGE_BYTES) throw new Error('image exceeds the size limit')
        const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
        await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
        const user = await UserModel.findByPk(loggedInUser.data.id)
        await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
      } catch (error) {
        logger.warn(`Rejected profile image URL for user ${loggedInUser.data.id}: ${utils.getErrorMessage(error)}`)
        res.status(400).json({ error: 'The profile image URL was rejected' })
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
