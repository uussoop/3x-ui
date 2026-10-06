import { useTranslation } from 'react-i18next';
import { InputNumber, Select } from 'antd';
import TextArea from 'antd/es/input/TextArea';

import { FormField } from '@/components/form/rhf';

export default function IKEv2Fields() {
  const { t } = useTranslation();
  return (
    <>
      <FormField name={['settings', 'mode']} label={t('pages.xray.ikev2.mode')}>
        <Select
          options={[
            { label: t('pages.xray.ikev2.modeServer'), value: 'server' },
            { label: t('pages.xray.ikev2.modeClient'), value: 'client' },
          ]}
        />
      </FormField>
      <FormField name={['settings', 'port']} label={t('pages.inbounds.port')}>
        <InputNumber min={1} max={65535} style={{ width: '100%' }} />
      </FormField>
      <FormField name={['settings', 'authMethod']} label={t('pages.xray.ikev2.authMethod')}>
        <Select
          options={[
            { label: t('pages.xray.ikev2.authEap'), value: 'eap-mschapv2' },
            { label: t('pages.xray.ikev2.authCert'), value: 'cert' },
            { label: t('pages.xray.ikev2.authPsk'), value: 'psk' },
          ]}
        />
      </FormField>
      <FormField name={['settings', 'caCert']} label={t('pages.xray.ikev2.caCert')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name={['settings', 'cert']} label={t('pages.xray.ikev2.cert')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
      <FormField name={['settings', 'key']} label={t('pages.xray.ikev2.key')}>
        <TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
      </FormField>
    </>
  );
}
