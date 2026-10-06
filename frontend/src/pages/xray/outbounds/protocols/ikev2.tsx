import { useTranslation } from 'react-i18next';
import { Input, InputNumber, Select } from 'antd';
import TextArea from 'antd/es/input/TextArea';

import { FormField } from '@/components/form/rhf';

export default function IKEv2OutboundFields() {
  const { t } = useTranslation();
  return (
    <>
      <FormField name="settings.remote" label={t('remote')}>
        <Input />
      </FormField>
      <FormField name="settings.port" label={t('pages.inbounds.port')}>
        <InputNumber min={1} max={65535} style={{ width: '100%' }} />
      </FormField>
      <FormField name="settings.authMethod" label={t('pages.xray.ikev2.authMethod')}>
        <Select
          options={[
            { label: t('pages.xray.ikev2.authEap'), value: 'eap-mschapv2' },
            { label: t('pages.xray.ikev2.authCert'), value: 'cert' },
            { label: t('pages.xray.ikev2.authPsk'), value: 'psk' },
          ]}
        />
      </FormField>
      <FormField name="settings.username" label={t('username')}>
        <Input />
      </FormField>
      <FormField name="settings.password" label={t('password')}>
        <Input.Password />
      </FormField>
      <FormField name="settings.psk" label={t('pages.xray.ikev2.psk')}>
        <Input.Password />
      </FormField>
      <FormField name="settings.caCert" label={t('pages.xray.ikev2.caCert')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name="settings.clientCert" label={t('pages.xray.ikev2.cert')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name="settings.clientKey" label={t('pages.xray.ikev2.key')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name="settings.probeTarget" label={t('pages.xray.ikev2.probeTarget')}>
        <Input placeholder="198.51.100.7:443" />
      </FormField>
      <FormField name="settings.probeDevice" label={t('pages.xray.ikev2.probeDevice')}>
        <Input />
      </FormField>
    </>
  );
}
