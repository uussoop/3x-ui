import { useTranslation } from 'react-i18next';
import { Input, InputNumber, Select } from 'antd';
import TextArea from 'antd/es/input/TextArea';

import { FormField } from '@/components/form/rhf';

export default function OpenVPNFields() {
  const { t } = useTranslation();
  return (
    <>
      <FormField name={['settings', 'mode']} label={t('pages.xray.openvpn.mode')}>
        <Select
          options={[
            { label: t('pages.xray.openvpn.modeServer'), value: 'server' },
            { label: t('pages.xray.openvpn.modeClient'), value: 'client' },
          ]}
        />
      </FormField>
      <FormField name={['settings', 'port']} label={t('pages.inbounds.port')}>
        <InputNumber min={1} max={65535} style={{ width: '100%' }} />
      </FormField>
      <FormField name={['settings', 'proto']} label={t('pages.xray.openvpn.proto')}>
        <Select
          options={[
            { label: t('pages.xray.openvpn.protoUdp'), value: 'udp' },
            { label: t('pages.xray.openvpn.protoTcp'), value: 'tcp' },
          ]}
        />
      </FormField>
      <FormField name={['settings', 'dev']} label={t('pages.xray.openvpn.dev')}>
        <Input placeholder="tun" />
      </FormField>
      <FormField name={['settings', 'ca']} label={t('pages.xray.openvpn.ca')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name={['settings', 'cert']} label={t('pages.xray.openvpn.cert')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name={['settings', 'key']} label={t('pages.xray.openvpn.key')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
    </>
  );
}
