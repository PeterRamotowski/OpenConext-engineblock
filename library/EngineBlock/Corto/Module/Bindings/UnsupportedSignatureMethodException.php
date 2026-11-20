<?php

/**
 * Copyright 2010 SURFnet B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException extends EngineBlock_Corto_Module_Bindings_Exception
{
    /**
     * @var string $signatureMethod
     */
    private $signatureMethod;

    /**
     * EngineBlock_Corto_Module_Bindings_UnsupportedSignatureMethodException constructor.
     * @param string $signatureMethod
     */
    public function __construct($signatureMethod, ?string $message = null, ?Exception $previous = null)
    {
        parent::__construct(
            $message ?? sprintf(
                'The signature method %s is not supported',
                $signatureMethod
            ),
            self::CODE_ERROR,
            $previous
        );

        $this->signatureMethod = $signatureMethod;
    }

    /**
     * The signature method configured for a remote entity cannot be used to sign messages for it.
     */
    public static function forRemoteEntity(string $signatureMethod, string $entityId, ?Exception $previous = null): self
    {
        return new self(
            $signatureMethod,
            sprintf(
                'The signature method %s configured for entity "%s" is not supported for signing',
                $signatureMethod,
                $entityId
            ),
            $previous
        );
    }

    /**
     * @return string
     */
    public function getSignatureMethod()
    {
        return $this->signatureMethod;
    }
}
