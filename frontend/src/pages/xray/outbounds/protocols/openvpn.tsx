import { useTranslation } from 'react-i18next';
import { Input, InputNumber, Select } from 'antd';
import TextArea from 'antd/es/input/TextArea';

import { FormField } from '@/components/form/rhf';

export default function OpenVPNOutboundFields() {
  const { t } = useTranslation();
  return (
    <>
      <FormField name="settings.remote" label={t('pages.xray.openvpn.remote')}>
        <Input />
      </FormField>
      <FormField name="settings.port" label={t('pages.inbounds.port')}>
        <InputNumber min={1} max={65535} style={{ width: '100%' }} />
      </FormField>
      <FormField name="settings.proto" label={t('pages.xray.openvpn.proto')}>
        <Select
          options={[
            { label: t('pages.xray.openvpn.protoUdp'), value: 'udp' },
            { label: t('pages.xray.openvpn.protoTcp'), value: 'tcp' },
          ]}
        />
      </FormField>
      <FormField name="settings.authUserPass" label={t('pages.xray.openvpn.authUserPass')}>
        <Input.Password />
      </FormField>
      <FormField name="settings.config" label={t('pages.xray.openvpn.profile')}>
        <TextArea autoSize={{ minRows: 4, maxRows: 10 }} />
      </FormField>
      <FormField name="settings.ca" label={t('pages.xray.openvpn.ca')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name="settings.cert" label={t('pages.xray.openvpn.cert')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name="settings.key" label={t('pages.xray.openvpn.key')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name="settings.probeTarget" label={t('pages.xray.openvpn.probeTarget')}>
        <Input placeholder="198.51.100.7:443" />
      </FormField>
      <FormField name="settings.probeDevice" label={t('pages.xray.openvpn.probeDevice')}>
        <Input />
      </FormField>
    </>
  );
}
