import { Switch } from '@headlessui/react'
import { type ActionFunctionArgs } from '@remix-run/node'
import { json, useFetcher, useLoaderData } from '@remix-run/react'
import clsx from 'clsx'
import { useState } from 'react'

import Button from '~/components/Button'
import Code from '~/components/Code'
import Input from '~/components/Input'
import TableList from '~/components/TableList'
import { getConfig, patchConfig } from '~/utils/config'
import { restartHeadscale } from '~/utils/docker'

import Domains from './domains'
import MagicModal from './magic'
import RenameModal from './rename'

// We do not want to expose every config value
export async function loader() {
	const config = await getConfig()
	const dns = {
		prefixes: config.prefixes,
		magicDns: config.dns_config.magic_dns,
		baseDomain: config.dns_config.base_domain,
		overrideLocal: config.dns_config.override_local_dns,
		nameservers: config.dns_config.nameservers,
		splitDns: config.dns_config.restricted_nameservers,
		searchDomains: config.dns_config.domains,
		extraRecords: config.dns_config.extra_records
	}

	return dns
}

export async function action({ request }: ActionFunctionArgs) {
	const data = await request.json() as Record<string, unknown>
	await patchConfig(data)
	await restartHeadscale()
	return json({ success: true })
}

export default function Page() {
	const data = useLoaderData<typeof loader>()
	const fetcher = useFetcher()
	const [localOverride, setLocalOverride] = useState(data.overrideLocal)
	const [ns, setNs] = useState('')

	return (
		<div className='flex flex-col gap-16 max-w-screen-lg'>
			<RenameModal name={data.baseDomain}/>
			<div className='flex flex-col w-2/3'>
				<h1 className='text-2xl font-medium mb-4'>Nameservers</h1>
				<p className='text-gray-700 dark:text-gray-300'>
					Set the nameservers used by devices on the Tailnet
					to resolve DNS queries.
				</p>
				<div className='mt-4'>
					<div className='flex items-center justify-between mb-2'>
						<h2 className='text-md font-medium opacity-80'>
							Global Nameservers
						</h2>
						<div className='flex gap-2 items-center'>
							<span className='text-sm opacity-50'>Override local DNS</span>
							<Switch
								checked={localOverride}
								className={clsx(
									localOverride ? 'bg-gray-800' : 'bg-gray-200',
									'relative inline-flex h-4 w-9 items-center rounded-full'
								)}
								onChange={() => {
									fetcher.submit({
										// eslint-disable-next-line @typescript-eslint/naming-convention
										'dns_config.override_local_dns': !localOverride
									}, {
										method: 'PATCH',
										encType: 'application/json'
									})

									setLocalOverride(!localOverride)
								}}
							>
								<span className='sr-only'>Override local DNS</span>
								<span
									className={clsx(
										localOverride ? 'translate-x-6' : 'translate-x-1',
										'inline-block h-2 w-2 transform rounded-full bg-white transition'
									)}
								/>
							</Switch>
						</div>
					</div>
					<TableList>
						{data.nameservers.map((ns, index) => (
							// eslint-disable-next-line react/no-array-index-key
							<TableList.Item key={index}>
								<p className='font-mono text-sm'>{ns}</p>
								<Button
									variant='destructive'
									className='text-sm'
									onClick={() => {
										fetcher.submit({
											// eslint-disable-next-line @typescript-eslint/naming-convention
											'dns_config.nameservers': data.nameservers.filter((_, index_) => index_ !== index)
										}, {
											method: 'PATCH',
											encType: 'application/json'
										})
									}}
								>
									Remove
								</Button>
							</TableList.Item>
						))}
						<TableList.Item>
							<Input
								variant='embedded'
								type='text'
								className='font-mono text-sm'
								placeholder='Nameserver'
								value={ns}
								onChange={event => {
									setNs(event.target.value)
								}}
							/>
							<Button
								className='text-sm'
								disabled={ns.length === 0}
								onClick={() => {
									fetcher.submit({
										// eslint-disable-next-line @typescript-eslint/naming-convention
										'dns_config.nameservers': [...data.nameservers, ns]
									}, {
										method: 'PATCH',
										encType: 'application/json'
									})

									setNs('')
								}}
							>
								Add
							</Button>
						</TableList.Item>
					</TableList>
					{/* TODO: Split DNS and Custom A Records */}
				</div>
			</div>

			<Domains
				baseDomain={data.magicDns ? data.baseDomain : undefined}
				searchDomains={data.searchDomains}
			/>

			<div className='flex flex-col w-2/3'>
				<h1 className='text-2xl font-medium mb-4'>Magic DNS</h1>
				<p className='text-gray-700 dark:text-gray-300 mb-4'>
					Automaticall register domain names for each device
					on the tailnet. Devices will be accessible at
					{' '}
					<Code>
						[device].[user].{data.baseDomain}
					</Code>
					{' '}
					when Magic DNS is enabled.
				</p>
				<MagicModal isEnabled={data.magicDns}/>
			</div>
		</div>
	)
}
